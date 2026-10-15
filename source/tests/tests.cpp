// Offline tests use synthetic identities and tickets; no CA or KDC is contacted.
#include "../src/directory.hpp"
#include "../src/enroll.hpp"
#include "../src/maintain.hpp"
#include "../src/pkinit.hpp"
#include "audit-collector.hpp"
#include "fuzz-targets.hpp"
#include "harness.hpp"
#include <sys/mman.h>
#include <filesystem>
#include <thread>
using namespace craft;
using testing::failed;

static constexpr char SID_OID[] = "1.3.6.1.4.1.311.25.2";
static constexpr char OBJECTSID_OID[] = "1.3.6.1.4.1.311.25.2.1";

static const krb5_creds *maintenance_grant = nullptr;
static unsigned maintenance_renewals = 0;

// Substitute only the KDC exchange while exercising real cache reads, validation and publication.
extern "C" krb5_error_code
__real_krb5_get_renewed_creds(krb5_context, krb5_creds *, krb5_principal, krb5_ccache, const char *);
extern "C" krb5_error_code __wrap_krb5_get_renewed_creds(
    krb5_context ctx, krb5_creds *creds, krb5_principal client, krb5_ccache cache, const char *service)
{
    if (!maintenance_grant) return __real_krb5_get_renewed_creds(ctx, creds, client, cache, service);
    ++maintenance_renewals;
    krb5_creds *copy = nullptr;
    const auto code = krb5_copy_creds(ctx, maintenance_grant, &copy);
    if (code) return code;
    *creds = *copy;
    *copy = {};
    krb5_free_creds(ctx, copy);
    return 0;
}

// OpenSSL keeps a per-thread error queue; start and leave each check with it empty.
static void test(std::string_view name, std::invocable auto &&f)
{
    ERR_clear_error();
    testing::test(name, f);
}

static void rejects(std::invocable auto &&f)
{
    testing::rejects(f);
    ERR_clear_error();
}

static Config with_source(Config cfg, CertificateSource source)
{
    cfg.source = source;
    return cfg;
}

static Bytes biobytes(BIO *b)
{
    const auto view = bioview(b);
    return {view.begin(), view.end()};
}

static void publish(const Account &caller, ByteView cache)
{
    publish_cache(caller_home(caller).get(), cache);
}

static void add_ext(X509 *c, Ext e)
{
    sslneed(X509_add_ext(c, e.get(), -1) == 1, "fixture add extension");
}

static void remove_ext(X509 *c, const char *oid)
{
    Obj o(OBJ_txt2obj(oid, 1));
    int i = X509_get_ext_by_OBJ(c, o.get(), -1);
    need(i >= 0, "fixture extension absent");
    Ext removed(X509_delete_ext(c, i));
}

static void set_ext_conf(X509 *c, int nid, const char *value)
{
    add_ext(c, conf_extension(nid, value));
}

static Cert fixture(EVP_PKEY *key, X509_REQ *req = nullptr)
{
    Cert c(X509_new());
    sslneed(c && X509_set_version(c.get(), 2) == 1, "fixture cert");
    sslneed(ASN1_INTEGER_set(X509_get_serialNumber(c.get()), 42) == 1 && X509_set_pubkey(c.get(), key) == 1,
            "fixture identity");

    X509_NAME *name = X509_get_subject_name(c.get());
    sslneed(X509_NAME_add_entry_by_txt(name,
                                       "CN",
                                       MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char *>("OFFLINE TEST ONLY"),
                                       -1,
                                       -1,
                                       0) == 1,
            "fixture name");
    sslneed(X509_set_issuer_name(c.get(), name) == 1, "fixture issuer");

    sslneed(X509_gmtime_adj(X509_getm_notBefore(c.get()), -60) &&
                X509_gmtime_adj(X509_getm_notAfter(c.get()), 600),
            "fixture times");

    if (req)
    {
        Extensions exts(X509_REQ_get_extensions(req));
        need(exts != nullptr, "fixture CSR extensions");
        for (int i = 0; i < sk_X509_EXTENSION_num(exts.get()); ++i)
            sslneed(X509_add_ext(c.get(), sk_X509_EXTENSION_value(exts.get(), i), -1) == 1,
                    "fixture copy extension");

        const std::string sid = "S-1-5-21-111-222-333-1101";
        Bytes v(sid.begin(), sid.end());
        add_ext(c.get(),
                raw_extension(SID_OID,
                              der(0x30, der(0xa0, join(oid_der(OBJECTSID_OID), der(0xa0, der(0x04, v)))))));
    }
    else
    {
        set_ext_conf(c.get(), NID_ext_key_usage, AGENT_OID);
    }

    if (X509_get_ext_by_NID(c.get(), NID_basic_constraints, -1) < 0)
        set_ext_conf(c.get(), NID_basic_constraints, "critical,CA:FALSE");

    sslneed(X509_sign(c.get(), key, EVP_sha256()) > 0, "fixture certificate signature");
    return c;
}

static std::string response_xml(const Bytes &data, const std::string &value_type = X509_TOKEN)
{
    return std::string("<s:Envelope xmlns:s=\"") + SOAP_NS + "\" xmlns:t=\"" + TRUST_NS + "\" xmlns:o=\"" +
           SECURITY_NS +
           "\"><s:Body><t:RequestSecurityTokenResponseCollection><t:RequestSecurityTokenResponse><t:"
           "RequestedSecurityToken><o:BinarySecurityToken EncodingType=\"" +
           SECURITY_NS + "#base64binary\" ValueType=\"" + value_type + "\">" + base64(data) +
           "</o:BinarySecurityToken></t:RequestedSecurityToken></t:RequestSecurityTokenResponse></"
           "t:RequestSecurityTokenResponseCollection></s:Body></s:Envelope>";
}

static krb5_creds make_test_creds(krb5_principal client,
                                  krb5_principal server,
                                  std::span<unsigned char> keydata,
                                  krb5_timestamp now,
                                  krb5_enctype enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                                  uint32_t tgt_seconds = 36000,
                                  uint32_t renew_seconds = 604800)
{
    krb5_creds creds{};
    creds.client = client;
    creds.server = server;
    creds.keyblock = {.magic = 0,
                      .enctype = enctype,
                      .length = static_cast<unsigned int>(keydata.size()),
                      .contents = keydata.data()};
    creds.times = {.authtime = now,
                   .starttime = now,
                   .endtime = static_cast<krb5_timestamp>(now + tgt_seconds),
                   .renew_till = static_cast<krb5_timestamp>(renew_seconds ? now + renew_seconds : 0)};
    creds.ticket_flags = TKT_FLG_INITIAL | TKT_FLG_PRE_AUTH;
    if (renew_seconds > 0) creds.ticket_flags |= TKT_FLG_RENEWABLE;
    return creds;
}

static void helper_tests()
{
    static_assert(!std::copy_constructible<Fd> && std::movable<Fd>);

    test("Linux account names enforce ASCII syntax and length boundaries",
         []
         {
             for (auto name : {"alice", "alice.smith", "_", "_service-1", "a_1.b-c"})
                 need(simple_name(name), "valid name rejected");
             need(simple_name(std::string(64, 'a')), "64-character name rejected");
             for (auto name :
                  {"", "../alice", "alice@domain.local", "-alice", "1alice", "Alice", "alice ", "alice\n"})
                 need(!simple_name(name), "invalid name accepted");
             need(!simple_name(std::string(65, 'a')) && !simple_name(std::string_view("alice\0x", 7)) &&
                      !simple_name(std::string_view("a\xff", 2)),
                  "oversized or non-ASCII name accepted");
         });

    test("unsigned parsing boundaries and full input consumption",
         []
         {
             need(number("0") == 0 && number("4294967295") == UINT32_MAX, "integer boundaries");
             need(number("00012") == 12 && number("60", 60) == 60, "leading zeros or cap");
             for (auto text : {"", "+1", "-1", " 1", "1 ", "1x", "4294967296", "00000000000"})
                 rejects([&] { number(text); });
             rejects([] { number("61", 60); });
         });

    test("empty spans and empty sealed memory files",
         []
         {
             const ByteView empty;
             auto file = memory_file("empty-test", empty);
             write_all(file.get(), empty);
             need(read_all(file.get(), 0).empty(), "empty read");
             need(base64(empty).empty(), "empty base64");
         });

    test("subspan transfers only the requested bytes",
         []
         {
             const std::array<unsigned char, 5> bytes{9, 1, 2, 3, 9};
             auto file = memory_file("span-test", std::span(bytes).subspan(1, 3));
             need(read_all(file.get()) == Bytes({1, 2, 3}), "span bounds");
         });

    test("bounded reads reject oversized input",
         []
         {
             auto file = memory_file("bounded-test", Bytes{1, 2, 3, 4});
             rejects([&] { read_all(file.get(), 3); });
             sysneed(lseek(file.get(), 0, SEEK_SET) == 0, "rewind test file");
             rejects([&] { read_all(file.get(), 0); });
         });

    test("descriptor moves transfer and release ownership",
         []
         {
             auto first = memory_file("fd-test", Bytes{1});
             const int original = first.get();
             Fd second(std::move(first));
             need(first.get() == -1 && second.get() == original, "move construction");

             auto target = memory_file("old-fd-test", Bytes{2});
             const int old = target.get();
             target = std::move(second);
             errno = 0;
             need(second.get() == -1 && target.get() == original && fcntl(old, F_GETFD) == -1 &&
                      errno == EBADF,
                  "move assignment must close previous fd");

             Fd adopted(target.release());
             need(target.get() == -1 && read_all(adopted.get()) == Bytes{1}, "release ownership");
         });

    test("scope cleanup runs on normal and exceptional exit",
         []
         {
             int calls{};
             {
                 ScopeExit cleanup([&]() noexcept { ++calls; });
             }
             rejects(
                 [&]
                 {
                     ScopeExit cleanup([&]() noexcept { ++calls; });
                     fail("deliberate test exception");
                 });
             need(calls == 2, "cleanup did not run exactly once per scope");
         });

    test("scope cleanup can be dismissed",
         []
         {
             bool called = false;
             {
                 ScopeExit cleanup([&]() noexcept { called = true; });
                 cleanup.release();
             }
             need(!called, "dismissed cleanup ran");
         });

    test("secret buffers are erased through mutable spans",
         []
         {
             Bytes bytes{1, 2, 3, 4};
             wipe(std::span(bytes).subspan(1, 2));
             need(bytes == Bytes({1, 0, 0, 4}), "subspan wipe");
             wipe(bytes);
             wipe({});
             need(std::ranges::all_of(bytes, [](auto byte) { return byte == 0; }), "complete wipe");
         });

    const std::string valid =
        "enabled=yes\nmodes=enrollment\ndomain=domain.local\nrealm=DOMAIN.LOCAL\nnetbios=DOMAIN\n"
        "template_oid=1.3.6.1.4.1.311.21.8.999.1\nces_url=https://ca.domain.local/CES\nces_auth=mtls\n"
        "service_principal=submitter@DOMAIN.LOCAL\n";

    test("configuration defaults and explicit limits",
         [&]
         {
             const auto defaults = parse_config(valid);
             need(defaults.tgt == 36000 && defaults.renew == 604800 && defaults.cert_remaining == 36000 &&
                      defaults.cert_total == 36000 && defaults.require_full_tgt_lifetime &&
                      defaults.certificate_cn == "{user}" && defaults.interval == 60 &&
                      defaults.key_bits == 3072 && defaults.gc_url == "ldap://domain.local:3268" &&
                      defaults.gc_base_dn == "DC=domain,DC=local",
                  "default policy changed");

             const auto explicit_limits = parse_config(
                 valid +
                 "tgt_seconds=120\nrenew_seconds=240\ncert_remaining_max_seconds=300\ncert_total_max_seconds="
                 "600\nminimum_interval_seconds=90\ngc_url=ldap://"
                 "gc.custom:3268\ngc_base_dn=DC=custom,DC=local\n");
             need(explicit_limits.tgt == 120 && explicit_limits.renew == 240 &&
                      explicit_limits.cert_remaining == 300 && explicit_limits.cert_total == 600 &&
                      explicit_limits.interval == 90 && explicit_limits.gc_url == "ldap://gc.custom:3268" &&
                      explicit_limits.gc_base_dn == "DC=custom,DC=local",
                  "limits not parsed");

             need(parse_config(valid + "renew_seconds=0\n").renew == 0, "renew=0 not accepted");
         });

    test("configuration parses editable CN and explicit shorter-ticket consent",
         [&]
         {
             const auto c =
                 parse_config(valid + "certificate_cn=Linux {user}\nrequire_full_tgt_lifetime=no\n");
             need(c.certificate_cn == "Linux {user}" && !c.require_full_tgt_lifetime,
                  "new configuration controls not parsed");
             rejects([&] { parse_config(valid + "require_full_tgt_lifetime=maybe\n"); });
         });

    test("configuration accepts only the supported key sizes",
         [&]
         {
             for (const uint32_t bits : {2048U, 3072U, 4096U})
                 need(parse_config(valid + std::format("key_bits={}\n", bits)).key_bits == bits,
                      "supported key size rejected");
             for (auto setting :
                  {"key_bits=1024\n", "key_bits=512\n", "key_bits=8192\n", "key_bits=invalid\n"})
                 rejects([&] { parse_config(valid + setting); });
         });

    test("home credential configuration needs no enrollment settings",
         []
         {
             const std::string text = "enabled=yes\nmodes=home\ndomain=domain.local\nrealm=DOMAIN.LOCAL\n";
             const auto cfg = parse_config(text, CertificateSource::Home);
             need(cfg.domain == "domain.local" && cfg.realm == "DOMAIN.LOCAL" &&
                      cfg.service_principal.empty() && cfg.ces_url.empty() && cfg.tgt == 36000 &&
                      cfg.renew == 604800 && cfg.source == CertificateSource::Home,
                  "home configuration policy");
             rejects([&] { parse_config(text, CertificateSource::Enrollment); });
             rejects([] { parse_config("enabled=no\nmodes=home\ndomain=domain.local\nrealm=DOMAIN.LOCAL\n"); });
         });

    test("enabled modes preserve order, reject disabled selection and validate every enabled mode",
         [&]
         {
             auto text = valid;
             text.replace(text.find("modes=enrollment"), std::strlen("modes=enrollment"),
                          "modes=home key_trust enrollment constrained_delegation");
             text += "kt_dc_url=ldap://dc.domain.local\nservice_spns=cifs/files.domain.local@DOMAIN.LOCAL\n";
             const auto cfg = parse_config(text);
             need(cfg.modes == std::vector{CertificateSource::Home,
                                          CertificateSource::KeyTrust,
                                          CertificateSource::Enrollment,
                                          CertificateSource::ConstrainedDelegation},
                  "configured mode order changed");
             for (const auto mode : cfg.modes)
                 need(parse_config(text, mode).source == mode, "enabled mode could not be selected");
             rejects([&] { parse_config(valid, CertificateSource::Home); });
             rejects([&] { parse_config(text.substr(0, text.find("kt_dc_url="))); });
             for (const auto mode : {"home home", "home unknown", "home,enrollment", ""})
             {
                 auto bad = valid;
                 bad.replace(bad.find("modes=enrollment"), std::strlen("modes=enrollment"),
                             std::string("modes=") + mode);
                 rejects([&] { parse_config(bad); });
             }
             rejects([&] { parse_config(valid + "mechanism=enrollment\n"); });
         });

    test("key trust mode selects the directory path without CA settings",
         []
         {
             const std::string base = "enabled=yes\ndomain=domain.local\nrealm=DOMAIN.LOCAL\n"
                                      "modes=key_trust\nservice_principal=svc@DOMAIN.LOCAL\n"
                                      "kt_dc_url=ldap://dc.domain.local\n";
             const auto cfg = parse_config(base);
             need(cfg.source == CertificateSource::KeyTrust && cfg.kt_dc_url == "ldap://dc.domain.local" &&
                      cfg.service_principal == "svc@DOMAIN.LOCAL" && cfg.ces_url.empty() &&
                      cfg.template_oid.empty() && cfg.netbios.empty(),
                  "key trust configuration policy");

             // Both the writable DC URL and the directory service principal are mandatory for key trust.
             rejects(
                 [&]
                 {
                     parse_config("enabled=yes\ndomain=domain.local\nrealm=DOMAIN.LOCAL\n"
                                  "modes=key_trust\nservice_principal=svc@DOMAIN.LOCAL\n");
                 });
             rejects(
                 [&]
                 {
                     parse_config("enabled=yes\ndomain=domain.local\nrealm=DOMAIN.LOCAL\n"
                                  "modes=key_trust\nkt_dc_url=ldap://dc.domain.local\n");
                 });
             rejects([&]
                     { parse_config(base.substr(0, base.find("kt_dc_url=")) + "kt_dc_url=http://dc\n"); });
             rejects(
                 [&]
                 {
                     parse_config("enabled=yes\ndomain=domain.local\nrealm=DOMAIN.LOCAL\n"
                                  "modes=shadow\nservice_principal=svc@DOMAIN.LOCAL\n");
                 });

             // Active Directory refuses the GSSAPI security layer inside TLS, and no TLS trust is configured.
             const auto without_dc = base.substr(0, base.find("kt_dc_url="));
             rejects([&] { parse_config(without_dc + "kt_dc_url=ldaps://dc.domain.local\n"); });
             rejects([&] { parse_config(base + "gc_url=ldaps://gc.domain.local:3269\n"); });
             rejects([&] { parse_config(base + "gc_url=ldap://user@gc.domain.local\n"); });
         });

    test("configuration rejects disabled missing unknown and duplicate settings",
         [&]
         {
             rejects([&] { parse_config(valid + "enabled=yes\n"); });
             rejects([&] { parse_config(valid + "unknown=yes\n"); });
             rejects([&] { parse_config(valid + "service_principal=\n"); });
             rejects([&] { parse_config(std::string_view(valid).substr(12)); });
             auto disabled = valid;
             disabled.replace(8, 3, "no");
             rejects([&] { parse_config(disabled); });
         });

    test("configuration preserves lifetime rate and transport restrictions",
         [&]
         {
             for (auto setting : {"tgt_seconds=59\n",
                                  "tgt_seconds=604801\n",
                                  "renew_seconds=604801\n",
                                  "renew_seconds=30\n",
                                  "renew_seconds=36000\n",
                                  "minimum_interval_seconds=29\n",
                                  "cert_remaining_max_seconds=59\n",
                                  "cert_total_max_seconds=600\n"})
                 rejects([&] { parse_config(valid + setting); });

             auto negotiate = valid;
             negotiate.replace(negotiate.find("mtls"), 4, "negotiate");
             need(parse_config(negotiate).ces_negotiate && !parse_config(valid).ces_negotiate,
                  "CES authentication choice was not parsed");
             for (auto config : {valid, negotiate})
             {
                 const auto principal = config.find("service_principal=");
                 rejects([&] { parse_config(config.substr(0, principal)); });
                 rejects([&] { parse_config(config.substr(0, principal) + "service_principal=\n"); });
             }
             auto unsupported = valid;
             unsupported.replace(unsupported.find("mtls"), 4, "basic");
             rejects([&] { parse_config(unsupported); });
         });

    test("configuration rejects malformed DNS labels in domains and realms",
         [&]
         {
             for (auto domain :
                  {"-domain.local", "domain-.local", "domain..local", ".domain.local", "domain.local."})
             {
                 auto config = valid;
                 config.replace(config.find("domain.local"), 12, domain);
                 rejects([&] { parse_config(config); });
             }
             for (auto realm :
                  {"-DOMAIN.LOCAL", "DOMAIN-.LOCAL", "DOMAIN..LOCAL", ".DOMAIN.LOCAL", "DOMAIN.LOCAL."})
             {
                 auto config = valid;
                 config.replace(config.find("DOMAIN.LOCAL"), 12, realm);
                 rejects([&] { parse_config(config); });
             }
             for (auto domain : {std::string(64, 'a') + ".local",
                                 std::string("Domain.local"),
                                 std::string(63, 'a') + "." + std::string(63, 'b') + "." +
                                     std::string(63, 'c') + "." + std::string(63, 'd')})
             {
                 auto config = valid;
                 config.replace(config.find("domain.local"), 12, domain);
                 rejects([&] { parse_config(config); });
             }
             auto config = valid;
             config.replace(config.find("DOMAIN.LOCAL"), 12, "domain.local");
             rejects([&] { parse_config(config); });
         });

    test("domain_to_dn formats DNS domain to LDAP distinguished name",
         [&]
         {
             need(domain_to_dn("craft.lab") == "DC=craft,DC=lab", "domain DN conversion");
             need(domain_to_dn("sub.corp.example.com") == "DC=sub,DC=corp,DC=example,DC=com",
                  "nested domain DN");
             need(domain_to_dn("domain") == "DC=domain", "single part domain DN");
         });

    test("base64 strips permitted whitespace and rejects embedded padding",
         []
         {
             need(unbase64(" A Q\tI\rD\n") == Bytes({1, 2, 3}), "whitespace handling");
             for (auto text : {"", "    ", "A=AA", "AAAA====", "A", "AA\v="})
                 rejects([&] { unbase64(text); });
         });

    test("large base64 payloads decode within the response size bound",
         []
         {
             Bytes payload(MAX_BLOB, 0xa5);
             need(unbase64(base64(payload)) == payload, "large base64 roundtrip");
             rejects([] { unbase64(std::string(2 * MAX_BLOB + 1, 'A')); });
         });

    test("DER length boundaries preserve span payloads",
         []
         {
             for (size_t size : {0, 1, 127, 128, 255, 256, 65535, 65536})
             {
                 const Bytes payload(size, 42);
                 const auto encoded = der(0x04, payload);
                 size_t pos = 2, length = encoded[1];
                 if (length & 0x80)
                 {
                     const auto count = length & 0x7f;
                     length = 0;
                     for (size_t i = 0; i < count; ++i)
                         length = (length << 8) | encoded[pos++];
                 }
                 need(length == size && std::ranges::equal(ByteView(encoded).subspan(pos), payload),
                      "DER length or payload");
             }
         });

    test("HTTP receive callback rejects overflow and capacity exhaustion",
         []
         {
             char byte = 'x';
             std::string response;
             need(receive(&byte, SIZE_MAX, 2, &response) == 0 && response.empty(),
                  "callback multiplication overflow");
             response.resize(2 * MAX_BLOB, 'x');
             need(receive(&byte, 1, 1, &response) == 0 && response.size() == 2 * MAX_BLOB,
                  "callback size limit");
         });
}

// Process, descriptor and private-file primitives that the launcher, worker and maintainer rely on.
static void process_tests()
{
    using namespace craft::maintain;
    char directory[] = "/tmp/craft-process-XXXXXX";
    need(mkdtemp(directory) != nullptr, "process test directory");
    const Fd dir(open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    ScopeExit cleanup(
        [&]() noexcept
        {
            std::error_code ignored;
            std::filesystem::remove_all(directory, ignored);
        });
    const auto exists = [&](const char *name)
    {
        return faccessat(dir.get(), name, F_OK, AT_SYMLINK_NOFOLLOW) == 0;
    };

    test("diagnostics keep only bounded printable ASCII",
         []
         {
             need(sanitize_ascii("a\x1b[31m\nb\x7f\x9b"
                                 "c\xc2\x80") == "a [31m b  c  ",
                  "control or non-ASCII byte kept");
             need(sanitize_ascii(std::string(600, 'x')).size() == 500, "diagnostic not bounded");
         });

    test("audit records are bounded printable text, and submission fails without the logging service",
         [&]
         {
             testing::AuditCollector log(std::string(directory) + "/log");
             audit(LOG_NOTICE, "issued\nforged[1]: uid=0 \x1b[31m" + std::string(5000, 'x'));
             const auto record = log.next(true);
             need(record.starts_with(std::format("<{}>", LOG_AUTHPRIV | LOG_NOTICE)) &&
                      record.find(std::format(" craft[{}]: issued forged[1]: uid=0  [31mxxx", getpid())) !=
                          record.npos &&
                      record.size() < 1024 &&
                      std::ranges::none_of(record, [](unsigned char c) { return c < 32 || c > 126; }),
                  "audit record was not framed, bounded and reduced to printable text");
             testing::audit_socket = std::string(directory) + "/gone";
             rejects([] { audit(LOG_NOTICE, "unrecorded"); });
             need(!try_audit(LOG_NOTICE, "unrecorded"), "a lost audit record was reported as submitted");
         });

    test("a failure shows the caller its summary and keeps the detail for the audit log",
         [&]
         {
             const auto failure = [](std::invocable auto &&operation)
             {
                 try
                 {
                     operation();
                 }
                 catch (const std::exception &error)
                 {
                     return std::pair(std::string(error.what()), caller_notice(error));
                 }
                 fail("operation unexpectedly succeeded");
             };
             need(failure([] { fail("rate limit reached"); }).second == "rate limit reached",
                  "a plain summary was not shown as it is");
             const auto unexpected = failure([] { throw std::runtime_error("internal detail"); }).second;
             need(unexpected.starts_with("unexpected failure: see the system log under craft[") &&
                      unexpected.find("internal") == unexpected.npos,
                  "an unexpected failure was described to the caller");

             // System paths, configuration, server text and library text stay out of the caller's notice.
             const auto hides = [&](std::string_view detail, std::invocable auto &&operation)
             {
                 const auto [what, shown] = failure(operation);
                 if (what.find(detail) == what.npos || shown.find(detail) != shown.npos ||
                     shown.find(": see the system log under craft[") == shown.npos)
                     fail(std::format("caller notice '{}' for failure '{}'", shown, what));
             };
             hides("/proc/craft-missing", [] { (void)root_open("/proc/craft-missing"); });
             hides("secret_setting", [] { parse_config("enabled=yes\nsecret_setting=1\n"); });
             hides("Denied by policy 7",
                   []
                   {
                       parse_response(std::string("<s:Envelope xmlns:s=\"") + SOAP_NS +
                                          "\"><s:Body><s:Fault><s:Reason>Denied by policy 7</s:Reason>"
                                          "</s:Fault></s:Body></s:Envelope>",
                                      nullptr);
                   });
             hides("error:",
                   []
                   {
                       const Cert unreadable = read_cert(byte_view("-----BEGIN CERTIFICATE-----\nAA\n"));
                       sslneed(unreadable != nullptr, "read certificate");
                   });
             KrbContext context;
             need(krb5_init_context(out(context)) == 0, "notice test context");
             hides("KDC", [&] { krb_check(context.get(), KRB5_KDC_UNREACH, "user PKINIT"); });
         });

    test("64-bit unsigned parsing for timestamps",
         []
         {
             need(number<uint64_t>("18446744073709551615") == UINT64_MAX &&
                      number<uint64_t>("4294967296") == 4294967296ULL,
                  "64-bit boundaries");
             rejects([] { number<uint64_t>("18446744073709551616"); });
             rejects([] { number<uint64_t>(std::string(21, '1')); });
         });

    test("URLs are restricted to a plain scheme, host and path",
         []
         {
             for (auto url : {"https://ces.domain.local/CES",
                              "https://ces.domain.local:8443/a/b.svc/CES",
                              "https://[fe80::1]/x"})
                 need(plain_url(url, "https://"), "valid URL rejected");
             for (auto url : {"http://ces.domain.local/",
                              "https://",
                              "https:///path",
                              "https://user@host/",
                              "https://host/?q=1",
                              "https://host/#f",
                              "https://host/a b",
                              "https://host\\evil/",
                              "HTTPS://host/",
                              "https://:443/",
                              "https://host/\x7f"})
                 need(!plain_url(url, "https://"), "unsafe URL accepted");
             need(!plain_url("https://host/" + std::string(2048, 'a'), "https://"), "oversized URL accepted");
         });

    test("state records are a fixed size and replaced by one write",
         [&]
         {
             const Fd file = open_private(dir.get(), "record", O_RDWR | O_CREAT, "test record");
             need(file.get() >= 0 && read_record(file.get()).empty(), "new record is not empty");
             write_record(file.get(), "1700000000 3");
             write_record(file.get(), "17");
             struct stat st
             {
             };
             need(fstat(file.get(), &st) == 0 && st.st_size == static_cast<off_t>(RECORD_SIZE) &&
                      read_record(file.get()) == "17",
                  "record was not replaced in place");
             rejects([&] { write_record(file.get(), std::string(RECORD_SIZE, '1')); });
             need(read_record(file.get()) == "17", "rejected write changed the record");

             // Anything but an empty file or one whole record is refused.
             for (const size_t size : {size_t{11}, RECORD_SIZE + 1})
             {
                 need(ftruncate(file.get(), static_cast<off_t>(size)) == 0, "malformed record fixture");
                 rejects([&] { read_record(file.get()); });
             }
             need(ftruncate(file.get(), 0) == 0 && read_record(file.get()).empty(), "cleared record");
         });

    test("private files refuse links, other users' access and oversized content",
         [&]
         {
             struct stat st
             {
             };
             {
                 const Fd created = open_private(dir.get(), "private", O_RDWR | O_CREAT, "test file");
                 need(created.get() >= 0 && fstat(created.get(), &st) == 0 && (st.st_mode & 0777) == 0600,
                      "created file is not private");
             }
             errno = 0;
             need(open_private(dir.get(), "missing", O_RDONLY, "test file").get() < 0 && errno == ENOENT,
                  "missing file was not reported as absent");
             need(symlinkat("private", dir.get(), "link") == 0, "symlink fixture");
             rejects([&] { open_private(dir.get(), "link", O_RDONLY, "test file"); });
             need(linkat(dir.get(), "private", dir.get(), "hard", 0) == 0, "hard link fixture");
             rejects([&] { open_private(dir.get(), "private", O_RDONLY, "test file"); });
             need(unlinkat(dir.get(), "hard", 0) == 0 && fchmodat(dir.get(), "private", 0640, 0) == 0,
                  "mode fixture");
             rejects([&] { open_private(dir.get(), "private", O_RDONLY, "test file"); });
             need(open_private(dir.get(), "private", O_RDONLY, "test file", 0022).get() >= 0,
                  "readable file refused");
             need(fchmodat(dir.get(), "private", 0660, 0) == 0, "writable fixture");
             rejects([&] { open_private(dir.get(), "private", O_RDONLY, "test file", 0022); });
             need(fchmodat(dir.get(), "private", 0600, 0) == 0 &&
                      truncate((std::string(directory) + "/private").c_str(), MAX_BLOB) == 0,
                  "size fixture");
             off_t size = -1;
             need(open_private(dir.get(), "private", O_RDONLY, "test file", 0077, &size).get() >= 0 &&
                      size == static_cast<off_t>(MAX_BLOB),
                  "size was not reported");
             need(truncate((std::string(directory) + "/private").c_str(), MAX_BLOB + 1) == 0,
                  "oversize fixture");
             rejects([&] { open_private(dir.get(), "private", O_RDONLY, "test file"); });
             need(mkfifoat(dir.get(), "fifo", 0600) == 0, "FIFO fixture");
             rejects([&] { open_private(dir.get(), "fifo", O_RDONLY, "test file"); });
         });

    test("atomic replacement leaves a private file and no temporaries",
         [&]
         {
             replace_file(dir.get(), "target", byte_view("one"), true);
             replace_file(dir.get(), "target", byte_view("two"), false);
             const Fd file = open_private(dir.get(), "target", O_RDONLY, "replaced file");
             need(file.get() >= 0 && read_all(file.get()) == Bytes({'t', 'w', 'o'}), "replacement content");
             for (const auto &entry : std::filesystem::directory_iterator(directory))
                 need(entry.path().filename().string().find(".tmp.") == std::string::npos,
                      "temporary left behind");
         });

    test("issuance rate limit serializes attempts, counts refusals once and tolerates clock steps",
         [&]
         {
             const time_t now = 1700000000;
             {
                 const Fd first = rate_limit(dir.get(), 1234, 60, now);
                 rejects([&] { rate_limit(dir.get(), 1234, 60, now + 120); }); // still running
                 const Fd other = rate_limit(dir.get(), 4321, 60, now);        // another user is independent
             }
             rejects([&] { rate_limit(dir.get(), 1234, 60, now + 59); });
             {
                 // The refusal above must not have restarted the interval.
                 const Fd later = rate_limit(dir.get(), 1234, 60, now + 60);
             }
             {
                 // A clock stepped back restarts the interval instead of locking the user out until it
                 // catches up.
                 const Fd stepped = rate_limit(dir.get(), 1234, 60, now - 3600);
             }
             rejects([&] { rate_limit(dir.get(), 1234, 60, now - 3600 + 30); });
             const Fd record = open_private(dir.get(), "1234.lock", O_RDWR, "issuance lock");
             write_record(record.get(), "not a time");
             rejects([&] { rate_limit(dir.get(), 1234, 60, now); });
         });

    test("broker fallback shares one request admission without bypassing locks or restarting the cooldown",
         [&]
         {
             const time_t now = 1700000000;
             const auto request = random_hex(), other = random_hex();
             {
                 const Fd first = rate_limit(dir.get(), 5678, 60, now, request);
                 rejects([&] { rate_limit(dir.get(), 5678, 60, now + 1, request); });
             }
             {
                 const Fd next = rate_limit(dir.get(), 5678, 60, now + 1, request);
                 need(read_record(next.get()) == std::format("{} {}", now, request),
                      "fallback reset its request's cooldown");
             }
             rejects([&] { rate_limit(dir.get(), 5678, 60, now + 59, other); });
             const Fd admitted = rate_limit(dir.get(), 5678, 60, now + 60, other);
             need(read_record(admitted.get()) == std::format("{} {}", now + 60, other),
                  "a new request did not replace the admission identifier");
         });

    test("stale status and temporary files are pruned after a week; recent and unrelated files stay",
         [&]
         {
             const time_t now = time(nullptr);
             const auto make = [&](const char *name, time_t age)
             {
                 const Fd file(openat(dir.get(), name, O_WRONLY | O_CREAT | O_CLOEXEC, 0600));
                 const timespec times[2] = {{now - age, 0}, {now - age, 0}};
                 need(file.get() >= 0 && futimens(file.get(), times) == 0, "prune fixture");
             };
             const auto stale = {".krb5cc_craft.maintain.111.status",
                                 ".krb5cc_craft.tmp.0123",
                                 ".krb5cc_craft.maintain.333.status.tmp.abcd"};
             const auto kept = {".krb5cc_craft.maintain.222.status",
                                ".krb5cc_craft",
                                ".krb5cc_craft.lock",
                                ".krb5cc_craft.maintain.lock",
                                "unrelated.status"};
             for (const char *name : stale)
                 make(name, 8 * 86400);
             for (const char *name : kept)
                 make(name, std::string_view(name).ends_with("222.status") ? 86400 : 30 * 86400);
             prune_stale_files(dir.get(), now);
             for (const char *name : stale)
                 need(!exists(name), "stale file kept");
             for (const char *name : kept)
                 need(exists(name), "live or unrelated file removed");
         });

    test("forked children exit with their result and never unwind into the caller",
         []
         {
             Child good(fork_child([] { return 0; })), bad(fork_child([] { return 7; }));
             need(good.wait() && !bad.wait(), "child exit status lost");
             Child thrown(fork_child(
                 []() -> int
                 {
                     if (!freopen("/dev/null", "w", stderr)) return 0;
                     fail("deliberate child failure");
                 }));
             need(!thrown.wait(), "a failed child reported success");
             pid_t abandoned;
             {
                 Child sleeper(fork_child([] { return pause(); }));
                 abandoned = sleeper.pid();
             }
             need(kill(abandoned, 0) != 0 && errno == ESRCH, "an abandoned child was not killed and reaped");
         });

    for (const bool enumerate : {false, true})
        test(enumerate ? "descriptor cleanup by /proc enumeration closes everything above the kept range"
                       : "descriptor renumbering keeps exactly the requested descriptors",
             [&]
             {
                 Pipe kept = make_pipe(), dropped = make_pipe();
                 Child child(fork_child(
                     [&]() -> int
                     {
                         // Scatter inherited descriptors, including one far above the usual range.
                         for (int i = 0; i < 5; ++i)
                             if (dup(dropped.reader.get()) < 0) return 2;
                         if (fcntl(dropped.writer.get(), F_DUPFD, 500) < 0) return 2;
                         if (!enumerate) keep_only({kept.writer.get(), -1});
                         else
                         {
                             if (dup2(kept.writer.get(), 3) != 3) return 2;
                             close_listed_from(4);
                         }
                         for (int fd = 4; fd < 600; ++fd)
                             if (fcntl(fd, F_GETFD) != -1) return 3;
                         for (int fd = 0; fd < 4; ++fd)
                             if (fcntl(fd, F_GETFD) == -1) return 4;
                         return write(3, "k", 1) == 1 ? 0 : 5;
                     }));
                 kept.writer = Fd();
                 need(read_all(kept.reader.get(), 1) == Bytes{'k'} && child.wait(),
                      "descriptors leaked or were lost");
             });

    test("a process watching its input pipe ends when the peer goes, and anything but a pipe is left alone",
         []
         {
             Pipe alive = make_pipe(), ready = make_pipe();
             const pid_t watcher = fork_child(
                 [&]() -> int
                 {
                     alive.writer = Fd();
                     exit_with_peer(alive.reader.get());
                     if (write(ready.writer.get(), "r", 1) != 1) return 2;
                     poll(nullptr, 0, 5000);
                     return 0; // outlived its peer
                 });
             ScopeExit reap(
                 [&]() noexcept
                 {
                     kill(watcher, SIGKILL);
                     (void)waitpid_retry(watcher);
                 });
             ready.writer = Fd();
             alive.reader = Fd();
             char armed = 0;
             need(retry([&] { return read(ready.reader.get(), &armed, 1); }) == 1, "watcher did not arm");
             alive.writer = Fd();
             int status = 0;
             need(waitpid_retry(watcher, &status) == watcher, "reap watcher");
             reap.release();
             need(WIFSIGNALED(status) && WTERMSIG(status) == SIGIO, "watcher outlived its peer");

             // A peer that is already gone raises no signal, so arming must notice it; other files are
             // ignored.
             Child late(fork_child(
                 []() -> int
                 {
                     Pipe gone = make_pipe();
                     gone.writer = Fd();
                     try
                     {
                         exit_with_peer(gone.reader.get());
                     }
                     catch (const std::exception &)
                     {
                         return 0;
                     }
                     return 1;
                 }));
             need(late.wait(), "a peer gone before the watch was armed went unnoticed");
             const Fd null(open("/dev/null", O_RDONLY | O_CLOEXEC));
             exit_with_peer(null.get());
             need(null.get() >= 0 && !(fcntl(null.get(), F_GETFL) & O_ASYNC), "a non-pipe was watched");
         });

    if (getuid() != 0)
    {
        std::cout << "SKIP trusted-path, privilege-drop and cross-identity checks: they need root in a "
                     "disposable container\n";
        return;
    }

    test("the peer watch ends a process whose parent dropped to another identity before dying",
         []
         {
             // The launcher's situation: a parent-death signal would not be delivered here, because the
             // kernel sends it with the credentials the dying parent has left.
             sysneed(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0, "adopt the orphaned watcher");
             ScopeExit restore([]() noexcept { prctl(PR_SET_CHILD_SUBREAPER, 0); });
             Pipe report = make_pipe();
             Child parent(fork_child(
                 [&]() -> int
                 {
                     Pipe alive = make_pipe(), ready = make_pipe();
                     const pid_t watcher = fork_child(
                         [&]() -> int
                         {
                             alive.writer = Fd();
                             if (setresuid(65534, 65534, 65534) != 0) return 2;
                             exit_with_peer(alive.reader.get());
                             if (write(ready.writer.get(), "r", 1) != 1) return 3;
                             poll(nullptr, 0, 5000);
                             return 0; // outlived its parent
                         });
                     char byte;
                     ready.writer = Fd();
                     if (read(ready.reader.get(), &byte, 1) != 1) return 4;
                     if (write(report.writer.get(), &watcher, sizeof(watcher)) !=
                         static_cast<ssize_t>(sizeof(watcher)))
                         return 5;
                     return setresuid(65533, 65533, 65533) == 0 ? 0 : 6; // exits holding the pipe
                 }));
             report.writer = Fd();
             pid_t watcher = -1;
             need(read(report.reader.get(), &watcher, sizeof(watcher)) ==
                          static_cast<ssize_t>(sizeof(watcher)) &&
                      parent.wait(),
                  "watcher did not start");
             int status = 0;
             need(waitpid_retry(watcher, &status) == watcher && WIFSIGNALED(status) &&
                      WTERMSIG(status) == SIGIO,
                  "watcher outlived a parent of another identity");
         });

    test("trusted paths must be root-controlled regular files reached without symlinks",
         []
         {
             char trusted[] = "/run/craft-trusted-XXXXXX";
             need(mkdtemp(trusted) != nullptr && chmod(trusted, 0755) == 0, "trusted path fixture");
             const std::string base = trusted;
             ScopeExit remove(
                 [&]() noexcept
                 {
                     std::error_code ignored;
                     std::filesystem::remove_all(base, ignored);
                 });
             const auto make = [&](const std::string &name, mode_t mode)
             {
                 const Fd file(
                     open((base + "/" + name).c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
                 need(file.get() >= 0 && write(file.get(), "x", 1) == 1 && fchmod(file.get(), mode) == 0,
                      "trusted file");
             };
             make("public", 0644);
             make("secret", 0640);
             make("loose", 0664);
             make("program", 0755);
             make("setuid", 04755);
             make("foreign", 0644);
             need(mkdir((base + "/sub").c_str(), 0755) == 0 &&
                      symlink("sub", (base + "/sublink").c_str()) == 0 &&
                      symlink("public", (base + "/link").c_str()) == 0 &&
                      chown((base + "/foreign").c_str(), 65534, 0) == 0,
                  "trusted directory fixtures");
             make("sub/file", 0644);
             need(read_all(root_open(base + "/public").get()) == Bytes{'x'} &&
                      root_text(base + "/sub/file") == "x",
                  "trusted file unreadable");
             (void)root_open(base + "/secret", Trusted::Secret);
             (void)root_open(base + "/program", Trusted::Worker);
             (void)root_open(base + "/setuid", Trusted::Launcher);
             need(truncate((base + "/program").c_str(), 9 * MAX_BLOB) == 0, "large program fixture");
             (void)root_open(base + "/program", Trusted::Worker);
             for (const auto &path : {base + "/loose",
                                      base + "/link",
                                      base + "/sublink/file",
                                      base + "/foreign",
                                      base + "/missing",
                                      base + "/./public",
                                      base + "/sub/../public",
                                      base + "//public",
                                      base,
                                      std::string("run/relative")})
                 rejects([&] { require_trusted(path); });
             rejects([&] { require_trusted(base + "/public", Trusted::Secret); });
             rejects([&] { require_trusted(base + "/public", Trusted::Worker); });
             rejects([&] { require_trusted(base + "/public", Trusted::Launcher); });
             rejects([&] { require_trusted(base + "/setuid", Trusted::Worker); });
             rejects([&] { require_trusted(base + "/program"); });
             need(chmod((base + "/sub").c_str(), 0775) == 0, "writable parent fixture");
             rejects([&] { require_trusted(base + "/sub/file"); });
         });

    test("a privilege drop is permanent and leaves no dumps, new privileges or extra groups",
         []
         {
             Child child(fork_child(
                 []() -> int
                 {
                     const gid_t extra[] = {65534};
                     drop(65534, 65534, extra);
                     gid_t groups[4]{};
                     rlimit core{};
                     if (getgroups(4, groups) != 1 || groups[0] != 65534) return 2;
                     if (setuid(0) == 0 || seteuid(0) == 0 || setgid(0) == 0 || setgroups(0, nullptr) == 0)
                         return 3;
                     if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 || prctl(PR_GET_DUMPABLE) != 0) return 4;
                     if (getrlimit(RLIMIT_CORE, &core) != 0 || core.rlim_max != 0) return 5;
                     return umask(0) == 0077 ? 0 : 6;
                 }));
             need(child.wait(), "privilege drop left a way back or skipped hardening");
         });
}

static Bytes ticket_fixture(krb5_enctype enctype,
                            std::string_view service = "krbtgt",
                            std::string_view host = "DOMAIN.LOCAL")
{
    auto text = [](std::string_view value)
    {
        return der(0x1b, byte_view(value));
    };
    const auto version = der(0xa0, der(0x02, Bytes{5}));
    const auto realm = der(0xa1, text("DOMAIN.LOCAL"));
    const auto names = der(0x30, join(text(service), text(host)));
    const auto principal = der(0xa2, der(0x30, join(der(0xa0, der(0x02, Bytes{2})), der(0xa1, names))));
    const auto enc = der(0xa3,
                         der(0x30,
                             join(der(0xa0, der(0x02, Bytes{static_cast<unsigned char>(enctype)})),
                                  der(0xa2, der(0x04, byte_view("NOT-A-REAL-TICKET"))))));
    return der(0x61, der(0x30, join(join(join(version, realm), principal), enc)));
}

static void revision_tests(const Config &cfg, const Mapping &map, EVP_PKEY *key, X509_REQ *req, X509 *leaf)
{
    auto reject_leaf = [&](auto &&mutator)
    {
        Cert c(X509_dup(leaf));
        mutator(c.get());
        rejects([&] { validate_leaf(c.get(), key, map, cfg); });
    };

    test("ten-hour certificate accepted independently of renewal request",
         [&]
         {
             Cert c(X509_dup(leaf));
             const auto now = time(nullptr);
             sslneed(ASN1_TIME_set(X509_getm_notBefore(c.get()), now - 60) &&
                         ASN1_TIME_set(X509_getm_notAfter(c.get()), now + 35940),
                     "ten-hour fixture validity");
             need(validate_leaf(c.get(), key, map, cfg) > time(nullptr), "10h certificate rejected");
         });

    test("certificate total validity cannot exceed ten hours",
         [&]
         {
             reject_leaf(
                 [](X509 *c)
                 {
                     X509_gmtime_adj(X509_getm_notBefore(c), -601);
                     X509_gmtime_adj(X509_getm_notAfter(c), 36000);
                 });
         });

    test("missing non-CA constraint rejected",
         [&] { reject_leaf([](X509 *c) { remove_ext(c, "2.5.29.19"); }); });

    test("PKINIT-specific client EKU is required",
         [&]
         {
             reject_leaf(
                 [](X509 *c)
                 {
                     remove_ext(c, "2.5.29.37");
                     set_ext_conf(c, NID_ext_key_usage, "clientAuth,1.3.6.1.4.1.311.20.2.2");
                 });
         });

    test("CA signing key usage rejected",
         [&]
         {
             reject_leaf(
                 [](X509 *c)
                 {
                     remove_ext(c, "2.5.29.15");
                     set_ext_conf(c, NID_key_usage, "critical,digitalSignature,keyCertSign");
                 });
         });

    test("custom CN placeholders do not change the identity",
         [&]
         {
             Config custom = cfg;
             custom.certificate_cn = "Linux logon - {user} - {domain}";
             need(common_name(custom, "alice", map.upn) == "Linux logon - alice - domain.local",
                  "CN expansion");
             auto csr = make_request(
                 key, "alice@domain.local", cfg.template_oid, common_name(custom, "alice", map.upn));
             std::array<char, 128> actual{};
             X509_NAME_get_text_by_NID(
                 X509_REQ_get_subject_name(csr.get()), NID_commonName, actual.data(), actual.size());
             need(std::string(actual.data()) == common_name(custom, "alice", map.upn), "CSR CN differs");

             custom.certificate_cn = "{upn}";
             need(common_name(custom, "alice", map.upn) == "alice@domain.local", "UPN placeholder");
         });

    test("CN UPN placeholder preserves the actual directory identity literally",
         [&]
         {
             auto custom = cfg;
             custom.certificate_cn = "{upn}";
             need(common_name(custom, "alice", "alice$&@alt.example") == "alice$&@alt.example",
                  "directory UPN replaced or interpreted as replacement syntax");
         });

    test("CN rejects unknown placeholders controls and excessive length",
         [&]
         {
             for (const auto &pattern :
                  {std::string("{uid}"), std::string("bad\nCN"), std::string(65, 'a'), std::string{}})
             {
                 Config custom = cfg;
                 custom.certificate_cn = pattern;
                 rejects([&] { common_name(custom, "alice", map.upn); });
             }
         });

    test("CSR contains no enrollee-supplied SID",
         [&]
         {
             Extensions exts(X509_REQ_get_extensions(req));
             for (int i = 0; i < sk_X509_EXTENSION_num(exts.get()); ++i)
                 need(objtext(X509_EXTENSION_get_object(sk_X509_EXTENSION_value(exts.get(), i))) != SID_OID,
                      "SID must be supplied by the CA");
         });

    test("template extension accepts an OID with optional unsigned versions",
         [&]
         {
             for (const auto &versions :
                  {Bytes{},
                   der(0x02, Bytes{0}),
                   join(der(0x02, Bytes{0, 0xff, 0xff, 0xff, 0xff}), der(0x02, Bytes{1}))})
             {
                 Cert c(X509_dup(leaf));
                 remove_ext(c.get(), TEMPLATE_OID);
                 add_ext(c.get(),
                         raw_extension(TEMPLATE_OID, der(0x30, join(oid_der(cfg.template_oid), versions))));
                 need(certificate_template(c.get()) == cfg.template_oid, "valid template version rejected");
             }
         });

    test("template extension rejects malformed or excessive version fields",
         [&]
         {
             for (const auto &versions :
                  {der(0x0c, byte_view("1")),
                   der(0x02, Bytes{0xff}),
                   der(0x02, Bytes{1, 0, 0, 0, 0}),
                   join(der(0x02, Bytes{1}), join(der(0x02, Bytes{2}), der(0x02, Bytes{3})))})
             {
                 Cert c(X509_dup(leaf));
                 remove_ext(c.get(), TEMPLATE_OID);
                 add_ext(c.get(),
                         raw_extension(TEMPLATE_OID, der(0x30, join(oid_der(cfg.template_oid), versions))));
                 rejects([&] { certificate_template(c.get()); });
             }
         });

    test("RAII C-output adoption and cleanup survive exceptions",
         []
         {
             int freed = 0;
             const auto deleter = [&freed](int *p) noexcept
             {
                 if (p)
                 {
                     ++freed;
                     delete p;
                 }
             };
             using Pointer = std::unique_ptr<int, decltype(deleter)>;

             rejects(
                 [&]
                 {
                     Pointer pointer(nullptr, deleter);
                     const auto allocates_then_fails = [](int **target)
                     {
                         *target = new int(7);
                         return false;
                     };
                     need(allocates_then_fails(out(pointer)), "simulated C API failure");
                 });
             need(freed == 1, "C output leaked on error");

             Pointer pointer(new int(8), deleter);
             rejects([&] { (void)out(pointer); });
             need(*pointer == 8, "existing owner overwritten");
         });

    KrbContext context;
    need(krb5_init_secure_context(out(context)) == 0, "revision test context");
    const auto ctx = context.get();
    const auto client = parse_principal(ctx, "alice@DOMAIN.LOCAL"),
               server = tgs_principal(ctx, "DOMAIN.LOCAL");
    std::array<unsigned char, 32> keydata{};
    const auto now = static_cast<krb5_timestamp>(time(nullptr));
    krb5_creds creds = make_test_creds(client.get(), server.get(), keydata, now);

    auto reject_tgt = [&](auto &&mutator)
    {
        auto c = creds;
        mutator(c);
        rejects([&] { validate_tgt(ctx, cfg, c, client.get(), server.get(), now, now); });
    };

    test("ten-hour AES256 ticket with seven-day renewal accepted",
         [&] { validate_tgt(ctx, cfg, creds, client.get(), server.get(), now, now); });

    test("ten-hour AES128 ticket with seven-day renewal accepted",
         [&]
         {
             auto c = creds;
             c.keyblock.enctype = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
             c.keyblock.length = 16;
             validate_tgt(ctx, cfg, c, client.get(), server.get(), now, now);
         });

    test("DC-shortened four-hour ticket rejected in strict mode",
         [&] { reject_tgt([&](auto &c) { c.times.endtime = now + 14400; }); });

    test("explicit nonstrict mode accepts capped lifetime with warning",
         [&]
         {
             auto c = creds;
             c.times.endtime = now + 14400;
             auto policy = cfg;
             policy.require_full_tgt_lifetime = false;
             std::ostringstream warning;
             auto *previous = std::cerr.rdbuf(warning.rdbuf());
             ScopeExit restore([&]() noexcept { std::cerr.rdbuf(previous); });
             validate_tgt(ctx, policy, c, client.get(), server.get(), now, now);
             need(warning.str().find("14400") != std::string::npos, "no granted lifetime warning");
         });

    test("DC-shortened renewable lifetime rejected in strict mode",
         [&] { reject_tgt([&](auto &c) { c.times.renew_till = now + 86400; }); });

    test("explicit nonstrict mode accepts capped renewable lifetime with warning",
         [&]
         {
             auto c = creds;
             c.times.renew_till = now + 86400;
             auto policy = cfg;
             policy.require_full_tgt_lifetime = false;
             std::ostringstream warning;
             auto *previous = std::cerr.rdbuf(warning.rdbuf());
             ScopeExit restore([&]() noexcept { std::cerr.rdbuf(previous); });
             validate_tgt(ctx, policy, c, client.get(), server.get(), now, now);
             need(warning.str().find("86400") != std::string::npos, "no granted renewable lifetime warning");
         });

    test("forwardable and noninitial user tickets rejected",
         [&]
         {
             for (auto flag : {TKT_FLG_FORWARDABLE,
                               TKT_FLG_FORWARDED,
                               TKT_FLG_PROXIABLE,
                               TKT_FLG_PROXY,
                               TKT_FLG_MAY_POSTDATE,
                               TKT_FLG_INVALID})
                 reject_tgt([&](auto &c) { c.ticket_flags |= flag; });
             reject_tgt([&](auto &c) { c.ticket_flags &= ~TKT_FLG_INITIAL; });
         });

    test("excessive expired and unrequested renewable lifetimes rejected",
         [&]
         {
             reject_tgt([&](auto &c) { c.times.endtime += 6; });
             reject_tgt([&](auto &c) { c.times.endtime = now - 1; });
             reject_tgt([&](auto &c) { c.times.renew_till += 6; });
             reject_tgt([&](auto &c) { c.times.renew_till = c.times.endtime; });
             reject_tgt([&](auto &c) { c.ticket_flags &= ~TKT_FLG_RENEWABLE; });

             auto no_renew = cfg;
             no_renew.renew = 0;
             auto c_no_renew = creds;
             c_no_renew.ticket_flags &= ~TKT_FLG_RENEWABLE;
             c_no_renew.times.renew_till = 0;
             validate_tgt(ctx, no_renew, c_no_renew, client.get(), server.get(), now, now);

             rejects(
                 [&]
                 {
                     auto bad = c_no_renew;
                     bad.ticket_flags |= TKT_FLG_RENEWABLE;
                     validate_tgt(ctx, no_renew, bad, client.get(), server.get(), now, now);
                 });
             rejects(
                 [&]
                 {
                     auto bad = c_no_renew;
                     bad.times.renew_till = now + 604800;
                     validate_tgt(ctx, no_renew, bad, client.get(), server.get(), now, now);
                 });
         });

    test("RC4 and incorrect AES key lengths rejected",
         [&]
         {
             reject_tgt([&](auto &c) { c.keyblock.enctype = ENCTYPE_ARCFOUR_HMAC; });
             reject_tgt([&](auto &c) { c.keyblock.length = 16; });
         });

    test("unexpected user or service principal rejected",
         [&]
         {
             reject_tgt([&](auto &c) { c.client = server.get(); });
             reject_tgt([&](auto &c) { c.server = client.get(); });
         });

    test("outer TGT envelope accepts the SHA-1 and RFC 8009 AES types; session keys stay SHA-1 AES",
         [&]
         {
             for (auto type : {ENCTYPE_AES256_CTS_HMAC_SHA384_192, ENCTYPE_AES128_CTS_HMAC_SHA256_128})
                 reject_tgt([&](auto &c) { c.keyblock.enctype = type; });
             for (auto type : AES_TICKET_TYPES)
             {
                 auto encoded = ticket_fixture(type);
                 krb5_data data{.magic = 0,
                                .length = static_cast<unsigned>(encoded.size()),
                                .data = reinterpret_cast<char *>(encoded.data())};
                 need(ticket_enctype(ctx, data) == type, "outer enctype differs");
             }
         });

    test("outer TGT envelope rejects RC4 and malformed tickets",
         [&]
         {
             auto encoded = ticket_fixture(ENCTYPE_ARCFOUR_HMAC);
             krb5_data data{.magic = 0,
                            .length = static_cast<unsigned>(encoded.size()),
                            .data = reinterpret_cast<char *>(encoded.data())};
             rejects([&] { ticket_enctype(ctx, data); });
             data.length = 3;
             rejects([&] { ticket_enctype(ctx, data); });
         });
}

static void maintenance_tests()
{
    using namespace craft::maintain;
    test("maintenance options require an explicit job and bounded durations",
         []
         {
             auto parse = [](std::initializer_list<const char *> values)
             {
                 std::vector<char *> args;
                 for (auto value : values)
                     args.push_back(const_cast<char *>(value));
                 return options(static_cast<int>(args.size()), args.data());
             };
             auto normal = parse({"craft-maintain", "--watch-pid", "123", "--max-duration", "21d"});
             need(normal.watch == 123 && normal.maximum == 1814400 && !normal.status, "duration parsing");
             need(parse({"craft-maintain", "--status", "--watch-pid", "123"}).status, "status parsing");
             need(parse({"craft-maintain", "--help"}).help, "help parsing");
             rejects([&] { parse({"craft-maintain"}); });
             rejects([&] { parse({"craft-maintain", "--watch-pid", "0"}); });
             rejects([&] { parse({"craft-maintain", "--watch-pid", "1", "--watch-pid", "2"}); });
             rejects([&] { parse({"craft-maintain", "--watch-pid", "1", "--max-duration", "0d"}); });
             rejects([&] { parse({"craft-maintain", "--watch-pid", "1", "--max-duration", "2w"}); });
             rejects([&] { parse({"craft-maintain", "--watch-pid", "1", "--max-duration", "999999999d"}); });
         });

    const auto now = static_cast<krb5_timestamp>(time(nullptr));
    KrbContext context;
    need(krb5_init_context(out(context)) == 0, "maintenance test context");
    const auto ctx = context.get();
    const auto client = parse_principal(ctx, "alice@DOMAIN.LOCAL"),
               server = tgs_principal(ctx, "DOMAIN.LOCAL");
    std::array<unsigned char, 32> key{};
    auto ticket = ticket_fixture(ENCTYPE_AES256_CTS_HMAC_SHA1_96);
    auto tgt = make_test_creds(client.get(), server.get(), key, now);
    tgt.ticket = {.magic = 0,
                  .length = static_cast<unsigned int>(ticket.size()),
                  .data = reinterpret_cast<char *>(ticket.data())};

    test("cached TGT metadata cannot disguise a service ticket envelope",
         [&]
         {
             auto encoded = ticket_fixture(ENCTYPE_AES256_CTS_HMAC_SHA1_96, "cifs", "files.domain.local");
             auto bad = tgt;
             bad.ticket = {.magic = 0,
                           .length = static_cast<unsigned int>(encoded.size()),
                           .data = reinterpret_cast<char *>(encoded.data())};
             rejects([&] { validate_cached_tgt(ctx, bad, client.get(), server.get(), now); });
         });

    test("maintenance schedules renewal and weekly enrollment from actual deadlines",
         [&]
         {
             need(schedule(nullptr, now).action == Action::Enroll, "missing cache did not enroll");
             need(schedule(&tgt, now).action == Action::Idle && schedule(&tgt, now).delay == 900,
                  "healthy cache contacted the KDC");
             need(schedule(&tgt, now + 28800).action == Action::Renew, "eight-hour renewal threshold");
             need(schedule(&tgt, now + 36000).action == Action::Enroll, "expired ticket did not enroll");
             auto near_window = tgt;
             near_window.times.authtime = now - 6 * 86400;
             near_window.times.renew_till = now + 86400;
             need(schedule(&near_window, now).action == Action::Enroll, "renewal deadline did not enroll");
             auto shorter = tgt;
             shorter.times.endtime = now + 120;
             shorter.times.renew_till = now + 600;
             need(schedule(&shorter, now).action == Action::Idle && schedule(&shorter, now).delay == 96,
                  "short grants caused immediate enrollment");
             need(schedule(&shorter, now + 96).action == Action::Renew, "short grant renewal threshold");
             auto nonrenewable = tgt;
             nonrenewable.ticket_flags &= ~TKT_FLG_RENEWABLE;
             nonrenewable.times.renew_till = 0;
             need(schedule(&nonrenewable, now).action == Action::Idle,
                  "healthy nonrenewable ticket re-enrolled");
             need(schedule(&nonrenewable, now + 28800).action == Action::Enroll,
                  "nonrenewable ticket did not refresh near expiry");
         });

    auto old = tgt;
    old.times.authtime = now - 28800;
    old.times.starttime = old.times.authtime;
    old.times.endtime = now + 7200;
    old.times.renew_till = old.times.authtime + 604800;
    auto renewed = old;
    renewed.times.starttime = now;
    renewed.times.endtime = now + 36000;
    renewed.ticket_flags &= ~TKT_FLG_INITIAL;
    test("renewal accepts original authentication time and an unchanged absolute renewal window",
         [&]
         {
             validate_renewed_tgt(ctx, old, renewed, now);
             auto shorter = renewed;
             shorter.times.renew_till -= 3600;
             validate_renewed_tgt(ctx, old, shorter, now);
         });
    test("renewal rejects new windows, changed identities, excessive grants and prohibited flags",
         [&]
         {
             auto reject = [&](auto mutation)
             {
                 auto bad = renewed;
                 mutation(bad);
                 rejects([&] { validate_renewed_tgt(ctx, old, bad, now); });
             };
             reject([](auto &c) { c.times.renew_till += 1; });
             reject([](auto &c) { c.times.authtime += 1; });
             reject([](auto &c) { c.times.endtime += 6; });
             reject([&](auto &c) { c.times.endtime = old.times.endtime; });
             reject([](auto &c) { c.ticket_flags |= TKT_FLG_FORWARDABLE; });
             reject([](auto &c) { c.ticket_flags &= ~TKT_FLG_PRE_AUTH; });
             reject([](auto &c) { c.keyblock.enctype = ENCTYPE_ARCFOUR_HMAC; });
             reject([&](auto &c) { c.client = server.get(); });
         });

    char directory[] = "/tmp/craft-maintain-test-XXXXXX";
    need(mkdtemp(directory) != nullptr, "maintenance test directory");
    const Account caller{.uid = getuid(), .gid = getgid(), .name = "alice", .home = directory};
    ScopeExit cleanup(
        [&]() noexcept
        {
            for (auto name : {CACHE_NAME, CACHE_LOCK, "outside", "source", "lock", "target"})
                unlink((caller.home + "/" + name).c_str());
            rmdir(directory);
        });
    test("atomic cache publication retains private ownership and leaves the old inode readable",
         [&]
         {
             auto bytes = file_cache(ctx, old);
             publish(caller, bytes);
             Fd previous(open((caller.home + "/" + CACHE_NAME).c_str(), O_RDONLY | O_CLOEXEC));
             auto fresh = file_cache(ctx, renewed);
             publish(caller, fresh);
             const Fd current(open((caller.home + "/" + CACHE_NAME).c_str(), O_RDONLY | O_CLOEXEC));
             struct stat st
             {
             };
             need(fstat(current.get(), &st) == 0 && st.st_uid == caller.uid && (st.st_mode & 0777) == 0600,
                  "cache publication permissions");
             need(read_all(previous.get()) == bytes && read_all(current.get()) == fresh,
                  "publication lost an inode");
             wipe(bytes);
             wipe(fresh);
             need(chmod(directory, 0777) == 0, "make unsafe home fixture");
             rejects([&] { caller_home(caller); });
             need(chmod(directory, 0700) == 0, "restore home permissions");
         });
    test("cache locking refuses symlinks and serializes different processes",
         [&]
         {
             const Fd home = caller_home(caller);
             need(symlink("outside", (caller.home + "/lock").c_str()) == 0, "test lock symlink");
             rejects([&] { cache_lock(home.get(), "lock"); });
             unlink((caller.home + "/lock").c_str());
             Fd locked = cache_lock(home.get(), CACHE_LOCK);
             std::array<int, 2> descriptors{};
             need(pipe2(descriptors.data(), O_CLOEXEC) == 0, "lock test pipe");
             Fd reader(descriptors[0]), writer(descriptors[1]);
             const auto child = fork();
             need(child >= 0, "lock test fork");
             if (child == 0)
             {
                 locked = Fd();
                 reader = Fd();
                 const auto acquired = cache_lock(home.get(), CACHE_LOCK);
                 const unsigned char value = 1;
                 _exit(write(writer.get(), &value, 1) == 1 ? 0 : 1);
             }
             writer = Fd();
             ScopeExit reap(
                 [&]() noexcept
                 {
                     kill(child, SIGKILL);
                     waitpid(child, nullptr, 0);
                 });
             pollfd ready{reader.get(), POLLIN, 0};
             need(poll(&ready, 1, 100) == 0, "second process acquired held lock");
             locked = Fd();
             need(poll(&ready, 1, 2000) > 0, "second process did not acquire released lock");
             int status{};
             need(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                  "lock test child failed");
             reap.release();
         });
    test("renewed cache preserves usable service tickets and removes the old TGT and expired services",
         [&]
         {
             auto source = krb_owner<std::remove_pointer_t<krb5_ccache>, krb5_cc_close>(ctx);
             const auto filename = caller.home + "/source";
             need(krb5_cc_resolve(ctx, ("FILE:" + filename).c_str(), out(source)) == 0,
                  "resolve source cache fixture");
             need(krb5_cc_initialize(ctx, source.get(), client.get()) == 0 &&
                      krb5_cc_store_cred(ctx, source.get(), &old) == 0,
                  "source cache fixture");
             const auto service = parse_principal(ctx, "ldap/host@DOMAIN.LOCAL"),
                        expired = parse_principal(ctx, "cifs/host@DOMAIN.LOCAL");
             char service_ticket[] = "SYNTHETIC SERVICE";
             auto extra = old;
             extra.server = service.get();
             extra.ticket = {.magic = 0, .length = sizeof(service_ticket) - 1, .data = service_ticket};
             need(krb5_cc_store_cred(ctx, source.get(), &extra) == 0, "store service fixture");
             extra.server = expired.get();
             extra.times.endtime = now - 1;
             need(krb5_cc_store_cred(ctx, source.get(), &extra) == 0, "store expired fixture");
             auto bytes = renewed_cache(ctx, source.get(), renewed, now);
             publish(caller, bytes);
             wipe(bytes);
             auto target = krb_owner<std::remove_pointer_t<krb5_ccache>, krb5_cc_close>(ctx);
             need(krb5_cc_resolve(ctx, ("FILE:" + caller.home + "/" + CACHE_NAME).c_str(), out(target)) == 0,
                  "open renewed cache");
             krb5_cc_cursor cursor{};
             need(krb5_cc_start_seq_get(ctx, target.get(), &cursor) == 0, "iterate renewed fixture");
             ScopeExit end([&]() noexcept { krb5_cc_end_seq_get(ctx, target.get(), &cursor); });
             int count = 0;
             for (;;)
             {
                 krb5_creds found{};
                 ScopeExit free([&]() noexcept { krb5_free_cred_contents(ctx, &found); });
                 const auto code = krb5_cc_next_cred(ctx, target.get(), &cursor, &found);
                 if (code == KRB5_CC_END) break;
                 need(code == 0, "read renewed fixture");
                 if (krb5_principal_compare(ctx, found.server, server.get()))
                     need(found.times.endtime == renewed.times.endtime, "retained old TGT");
                 else
                     need(krb5_principal_compare(ctx, found.server, service.get()),
                          "retained expired service");
                 ++count;
             }
             need(count == 2, "renewed cache dropped or duplicated credentials");
         });
    for (const bool pidfd : {true, false})
        test(pidfd ? "pidfd observes job termination and refuses other Linux identities"
                   : "/proc watch observes job termination without pidfd_open, including an unreaped exit",
             [&]
             {
                 const auto child = fork();
                 need(child >= 0, "watch test fork");
                 if (child == 0)
                 {
                     poll(nullptr, 0, 2000);
                     _exit(0);
                 }
                 ScopeExit reap(
                     [&]() noexcept
                     {
                         kill(child, SIGKILL);
                         waitpid(child, nullptr, 0);
                     });
                 const auto watch = watch_process(child, getuid(), pidfd);
                 need(watch.pollable == pidfd && !exited(watch), "watcher ended prematurely");
                 rejects([&] { watch_process(child, getuid() + 1, pidfd); });
                 const auto soon = Clock::now() + std::chrono::milliseconds(50);
                 need(wait_for(watch, -1, soon) == Wake::Timeout, "live job reported as ended");
                 const Pipe other = make_pipe();
                 write_all(other.writer.get(), byte_view("x"));
                 need(wait_for(watch, other.reader.get(), soon + std::chrono::seconds(1)) == Wake::Readable,
                      "readable descriptor not reported");

                 // The job is a zombie until reaped: both forms must already see it as ended.
                 kill(child, SIGTERM);
                 need(wait_for(watch, -1, Clock::now() + std::chrono::seconds(5)) == Wake::Exited &&
                          exited(watch),
                      "job exit was not observed");
                 need(wait_for(watch, other.reader.get(), Clock::now() + std::chrono::seconds(1)) ==
                          Wake::Exited,
                      "job exit lost precedence over a readable descriptor");
                 need(waitpid(child, nullptr, 0) == child && exited(watch), "reaped job reported as live");
                 reap.release();
                 rejects([&] { watch_process(child, getuid(), pidfd); });
             });
    for (const bool pidfd : {true, false})
        test(pidfd ? "pidfd keeps a job live while any thread runs after its first thread ended"
                   : "/proc watch keeps a job live while any thread runs after its first thread ended",
             [&]
             {
                 const auto child = fork();
                 need(child >= 0, "threaded job fork");
                 if (child == 0)
                 {
                     std::thread(
                         []
                         {
                             poll(nullptr, 0, 1500);
                             _exit(0);
                         })
                         .detach();
                     pthread_exit(nullptr);
                 }
                 ScopeExit reap(
                     [&]() noexcept
                     {
                         kill(child, SIGKILL);
                         waitpid(child, nullptr, 0);
                     });
                 const auto watch = watch_process(child, getuid(), pidfd);

                 // Wait for the first thread to become a zombie while its sibling still runs.
                 const auto first_thread_ended = [&]
                 {
                     const Fd stat(open(std::format("/proc/{}/stat", child).c_str(), O_RDONLY | O_CLOEXEC));
                     return stat.get() >= 0 &&
                            text_of(read_all(stat.get(), 4096)).find(") Z ") != std::string::npos;
                 };
                 for (int i = 0; i < 100 && !first_thread_ended(); ++i)
                     poll(nullptr, 0, 10);
                 need(first_thread_ended() && !exited(watch),
                      "a job with a running thread was reported as ended");
                 need(wait_for(watch, -1, Clock::now() + std::chrono::seconds(5)) == Wake::Exited &&
                          exited(watch),
                      "the end of the last thread was not observed");
                 need(waitpid(child, nullptr, 0) == child, "reap threaded job");
                 reap.release();
             });
}

// The integration harness uses this synthetic issuer only inside a disposable test container.
static void maintenance_fixture(std::string_view mode)
{
    const Account caller = lookup_uid(getuid());
    need(caller.name == "craft-maintain-test" && caller.home == "/home/craft-maintain-test",
         "maintenance fixtures require the isolated craft-maintain-test account");
    KrbContext context;
    need(krb5_init_context(out(context)) == 0, "fixture Kerberos context");
    const auto ctx = context.get();
    const bool services = mode == "services" || mode == "services-due" || mode == "services-soon";
    const auto client = parse_principal(ctx, "craft-maintain-test@DOMAIN.LOCAL"),
               server = services ? parse_principal(ctx, "cifs/files.domain.local@DOMAIN.LOCAL")
                                 : tgs_principal(ctx, "DOMAIN.LOCAL");
    std::array<unsigned char, 32> key{};
    const auto now = static_cast<krb5_timestamp>(time(nullptr));
    auto tgt = make_test_creds(client.get(), server.get(), key, now);
    if (services)
    {
        tgt.ticket_flags = TKT_FLG_FORWARDABLE | TKT_FLG_FORWARDED | TKT_FLG_PRE_AUTH;
        tgt.times.renew_till = 0;
        if (mode == "services-due")
        {
            tgt.times.authtime = tgt.times.starttime = now - 32400;
            tgt.times.endtime = now + 3600;
        }
        else if (mode == "services-soon")
        {
            tgt.times.authtime = tgt.times.starttime = now - 25;
            tgt.times.endtime = now + 10;
        }
    }
    else if (mode == "renew" || mode == "nonrenewable")
    {
        tgt.times.authtime = tgt.times.starttime = now - 32400;
        tgt.times.endtime = now + 3600;
        tgt.times.renew_till = tgt.times.authtime + 604800;
        if (mode == "nonrenewable")
        {
            tgt.ticket_flags &= ~TKT_FLG_RENEWABLE;
            tgt.times.renew_till = 0;
        }
    }
    else if (mode == "expired")
    {
        tgt.times.authtime = tgt.times.starttime = now - 36001;
        tgt.times.endtime = now - 1;
        tgt.times.renew_till = tgt.times.authtime + 604800;
    }
    else if (mode == "rollover")
    {
        tgt.times.authtime = now - 6 * 86400 - 3600;
        tgt.times.renew_till = tgt.times.authtime + 604800;
    }
    else need(mode == "healthy", "unknown maintenance fixture");
    auto encoded = ticket_fixture(ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                                   services ? "cifs" : "krbtgt",
                                   services ? "files.domain.local" : "DOMAIN.LOCAL");
    tgt.ticket = {.magic = 0,
                  .length = static_cast<unsigned int>(encoded.size()),
                  .data = reinterpret_cast<char *>(encoded.data())};
    auto bytes = file_cache(ctx, tgt);
    publish(caller, bytes);
    wipe(bytes);
}

static void maintenance_update_tests()
{
    using namespace craft::maintain;
    maintenance_fixture("rollover");
    const Account caller = lookup_uid(getuid());
    const Fd home = caller_home(caller);
    KrbContext context;
    need(krb5_init_context(out(context)) == 0, "maintenance update context");
    const auto ctx = context.get();
    auto cache = krb_owner<std::remove_pointer_t<krb5_ccache>, krb5_cc_close>(ctx);
    KrbPrincipal client(nullptr, {ctx});
    const auto server = tgs_principal(ctx, "DOMAIN.LOCAL");
    need(krb5_cc_resolve(ctx, ("FILE:" + caller.home + "/" + CACHE_NAME).c_str(), out(cache)) == 0,
         "maintenance update cache");
    need(krb5_cc_get_principal(ctx, cache.get(), out(client)) == 0, "maintenance update principal");
    krb5_creds match{}, original{};
    match.client = client.get();
    match.server = server.get();
    need(krb5_cc_retrieve_cred(ctx, cache.get(), 0, &match, &original) == 0, "read rollover fixture");
    ScopeExit cleanup(
        [&]() noexcept
        {
            maintenance_grant = nullptr;
            krb5_free_cred_contents(ctx, &original);
        });
    auto read = [&](const char *name)
    {
        const Fd file(openat(home.get(), name, O_RDONLY | O_CLOEXEC));
        need(file.get() >= 0, "read maintenance update fixture");
        return read_all(file.get());
    };
    auto publish = [&](krb5_creds &tgt)
    {
        auto bytes = file_cache(ctx, tgt);
        ::publish(caller, bytes);
        wipe(bytes);
    };

    // Forget earlier issuances and the enrollment backoff, which is kept in the maintenance lock file.
    auto reset = [&]
    {
        need(unlinkat(home.get(), ".maintain-test-issuance", 0) == 0 || errno == ENOENT,
             "reset issuance count");
        const Fd lock = cache_lock(home.get(), MAINTAIN_LOCK);
        need(ftruncate(lock.get(), 0) == 0, "reset enrollment backoff");
    };
    const auto log_path = caller.home + "/.maintain-test-log";
    testing::AuditCollector log(log_path);

    test("enrollment denial and shared cooldown cannot postpone a due renewal",
         [&]
         {
             reset();
             const Fd mode(openat(home.get(), ".maintain-test-mode", O_WRONLY | O_CREAT | O_TRUNC, 0600));
             need(mode.get() >= 0, "deny test enrollment");
             write_all(mode.get(), byte_view("deny"));
             const auto now = static_cast<krb5_timestamp>(time(nullptr));
             auto due = original;
             due.times.starttime = now - 28800 + 30;
             due.times.endtime = now + 7200 + 30;
             publish(due);

             // An issuer failure must wake the loop by the renewal threshold without shortening shared
             // backoff.
             Result denied;
             rejects([&] { update(caller, {}, denied); });
             need(!denied.success && denied.retry > 0 && denied.retry <= 30,
                  "enrollment backoff delays renewal");
             const auto issuance = read(".maintain-test-issuance"), retry = read(MAINTAIN_LOCK);
             need(std::ranges::count(issuance, '\n') == 1, "enrollment denial was not exercised");
             std::istringstream retry_state(std::string(retry.begin(), retry.end()));
             int64_t next = 0;
             need(static_cast<bool>(retry_state >> next) && next >= now + 60,
                  "shared enrollment cooldown was shortened");
             Result waiting;
             rejects([&] { update(caller, {}, waiting); });
             need(waiting.retry > 0 && waiting.retry <= 30, "shared cooldown delays renewal");

             // Advance the cached ticket to its renewal threshold while the issuer remains in cooldown.
             due.times.starttime -= 60;
             due.times.endtime -= 60;
             publish(due);
             auto grant = due;
             grant.times.starttime = now;
             grant.times.endtime = now + 36000;
             grant.ticket_flags &= ~TKT_FLG_INITIAL;
             maintenance_grant = &grant;
             ScopeExit reset_grant([&]() noexcept { maintenance_grant = nullptr; });
             Result renewed;
             update(caller, {}, renewed);
             maintenance_grant = nullptr;
             need(renewed.success && maintenance_renewals == 1 && renewed.end == grant.times.endtime,
                  "rollover did not renew the usable TGT");
             need(log.records().find(std::format(
                      "renewed TGT uid={} expiry={}", caller.uid, grant.times.endtime)) != std::string::npos,
                  "the renewal left no audit record");
             need(read(".maintain-test-issuance") == issuance && read(MAINTAIN_LOCK) == retry,
                  "renewal bypassed or reset shared enrollment backoff");
             krb5_creds saved{};
             ScopeExit free([&]() noexcept { krb5_free_cred_contents(ctx, &saved); });
             need(krb5_cc_retrieve_cred(ctx, cache.get(), 0, &match, &saved) == 0 &&
                      saved.times.endtime == grant.times.endtime,
                  "renewed TGT was not published");

             // A ticket already at its absolute deadline must retain enrollment backoff instead of attempting
             // renewal.
             due.times.starttime = now - 300;
             due.times.endtime = due.times.renew_till = now + 60;
             publish(due);
             maintenance_grant = &grant;
             Result exhausted;
             rejects([&] { update(caller, {}, exhausted); });
             need(maintenance_renewals == 1 && exhausted.retry >= 45,
                  "an exhausted renewal window caused renewal or busy polling");
         });
    test("a renewal is not published while the logging service is unavailable",
         [&]
         {
             reset();
             const auto now = static_cast<krb5_timestamp>(time(nullptr));
             auto due = original;
             due.times.starttime = now - 28800 - 30;
             due.times.endtime = now + 7200 - 30;
             publish(due);
             auto grant = due;
             grant.times.starttime = now;
             grant.times.endtime = now + 36000;
             grant.ticket_flags &= ~TKT_FLG_INITIAL;
             maintenance_grant = &grant;
             ScopeExit restore(
                 [&]() noexcept
                 {
                     maintenance_grant = nullptr;
                     testing::audit_socket = log_path;
                 });
             const auto before = read(CACHE_NAME);
             testing::audit_socket = caller.home + "/.maintain-test-no-log";
             Result refused;
             rejects([&] { update(caller, {}, refused); });
             need(!refused.success && read(CACHE_NAME) == before, "an unrecorded renewal was published");
             testing::audit_socket = log_path;
             Result renewed;
             update(caller, {}, renewed);
             need(renewed.success && renewed.end == grant.times.endtime && read(CACHE_NAME) != before,
                  "the renewal did not resume once it could be recorded");
         });
    for (const bool near_expiry : {false, true})
        test(near_expiry ? "a renewal grant already due for renewal is revisited promptly"
                         : "a shortened renewal window triggers prompt enrollment",
             [&]
             {
                 reset();
                 const Fd mode(openat(home.get(), ".maintain-test-mode", O_WRONLY | O_CREAT | O_TRUNC, 0600));
                 need(mode.get() >= 0, "enable test enrollment");
                 write_all(mode.get(), byte_view("healthy"));
                 const auto now = static_cast<krb5_timestamp>(time(nullptr));
                 auto due = original;
                 due.times.starttime = now - 90;
                 due.times.endtime = now + 10;
                 publish(due);
                 auto grant = due;
                 grant.times.starttime = near_expiry ? now - 85 : now;
                 grant.times.endtime = now + (near_expiry ? 15 : 80);
                 if (!near_expiry) grant.times.renew_till = now + 90;
                 grant.ticket_flags &= ~TKT_FLG_INITIAL;
                 maintenance_grant = &grant;
                 maintenance_renewals = 0;
                 ScopeExit reset_grant([&]() noexcept { maintenance_grant = nullptr; });

                 // Accept and publish the shorter grant, then follow its immediate maintenance action.
                 Result shortened;
                 update(caller, {}, shortened);
                 need(shortened.success && shortened.end == grant.times.endtime && shortened.delay <= 1,
                      "accepted renewal grant postponed a required action");
                 grant.times.starttime = now;
                 grant.times.endtime = now + 100;
                 if (!near_expiry) maintenance_grant = nullptr;
                 Result refreshed;
                 update(caller, {}, refreshed);
                 need(refreshed.success && refreshed.end > shortened.end,
                      "follow-up did not extend the short grant");
                 if (near_expiry) need(maintenance_renewals == 2, "due renewal did not run again");
                 else
                     need(maintenance_renewals == 1 &&
                              std::ranges::count(read(".maintain-test-issuance"), '\n') == 1,
                          "shortened renewal window did not enroll once");
             });
}

static void user_identity_tests(const Config &cfg, const Mapping &map, EVP_PKEY *key, X509 *leaf)
{
    char path[] = "/tmp/craft-user-identity-XXXXXX";
    need(mkdtemp(path) != nullptr, "user identity test directory");
    const Account caller{.uid = getuid(), .gid = getgid(), .name = "alice", .home = path};
    const auto config_path = caller.home + "/.config", directory_path = config_path + "/craft";
    const Config home_cfg = with_source(cfg, CertificateSource::Home);
    ScopeExit cleanup(
        [&]() noexcept
        {
            for (const char *name : {"user.pem", "user.key", "held.key"})
                unlink((directory_path + "/" + name).c_str());
            rmdir(directory_path.c_str());
            rmdir(config_path.c_str());
            rmdir(path);
        });
    test("absent user identity directories and pair select enrollment",
         [&]
         {
             need(user_identity_files(caller).certificate.get() < 0,
                  "missing .config selected a certificate");
             need(mkdir(config_path.c_str(), 0700) == 0, "identity .config fixture");
             need(user_identity_files(caller).certificate.get() < 0,
                  "missing craft directory selected a certificate");
             need(mkdir(directory_path.c_str(), 0700) == 0, "identity directory fixture");
             need(user_identity_files(caller).certificate.get() < 0, "missing pair selected a certificate");
             need(chmod(config_path.c_str(), 0770) == 0, "unrelated writable .config fixture");
             need(user_identity_files(caller).certificate.get() < 0,
                  "empty writable directory blocked enrollment");
             need(chmod(config_path.c_str(), 0700) == 0, "restore .config fixture");
         });
    const Fd directory(open(directory_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    need(directory.get() >= 0, "open identity fixture directory");
    Bio certificate(BIO_new(BIO_s_mem())), private_key(BIO_new(BIO_s_mem()));
    sslneed(certificate && private_key && PEM_write_bio_X509(certificate.get(), leaf) == 1 &&
                PEM_write_bio_PrivateKey(private_key.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1,
            "PEM identity fixtures");
    const auto write = [&](const char *name, Bio &bio)
    {
        const Fd file(openat(directory.get(), name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
        need(file.get() >= 0, "open PEM fixture");
        Bytes bytes = biobytes(bio.get());
        ScopeExit erase([&]() noexcept { wipe(bytes); });
        write_all(file.get(), bytes);
    };
    write("user.pem", certificate);
    write("user.key", private_key);
    test("private home PEM pair loads using caller permissions",
         [&]
         {
             const auto files = user_identity_files(caller);
             auto identity = load_user_identity(files);
             need(X509_cmp(identity.certificate.get(), leaf) == 0 &&
                      validate_leaf(identity.certificate.get(), identity.key.get(), map, home_cfg) >
                          time(nullptr),
                  "loaded identity differs");
             auto other_caller = caller;
             other_caller.uid += 1;
             rejects([&] { user_identity_files(other_caller); });
         });
    test("opened identity survives file replacement without reopening paths",
         [&]
         {
             const auto files = user_identity_files(caller);
             need(renameat(directory.get(), "user.key", directory.get(), "held.key") == 0,
                  "hold private key inode");
             ScopeExit restore(
                 [&]() noexcept
                 {
                     unlinkat(directory.get(), "user.key", 0);
                     renameat(directory.get(), "held.key", directory.get(), "user.key");
                 });
             const Fd replacement(openat(directory.get(), "user.key", O_WRONLY | O_CREAT | O_EXCL, 0600));
             write_all(replacement.get(), byte_view("INVALID PRIVATE KEY"));
             auto identity = load_user_identity(files);
             sslneed(X509_check_private_key(identity.certificate.get(), identity.key.get()) == 1,
                     "identity followed replacement inode");
         });
    test("incomplete symlinked and nonregular private keys fail without enrollment",
         [&]
         {
             need(unlinkat(directory.get(), "user.key", 0) == 0, "remove fixture key");
             ScopeExit restore(
                 [&]() noexcept
                 {
                     try
                     {
                         write("user.key", private_key);
                     }
                     catch (...)
                     {
                     }
                 });
             rejects([&] { user_identity_files(caller); });
             need(symlinkat("user.pem", directory.get(), "user.key") == 0, "key symlink fixture");
             rejects([&] { user_identity_files(caller); });
             need(unlinkat(directory.get(), "user.key", 0) == 0 &&
                      mkfifoat(directory.get(), "user.key", 0600) == 0,
                  "key FIFO fixture");
             rejects([&] { user_identity_files(caller); });
             need(unlinkat(directory.get(), "user.key", 0) == 0, "remove key FIFO");
         });
    test("unsafe key and identity directory permissions fail",
         [&]
         {
             need(fchmodat(directory.get(), "user.key", 0644, 0) == 0, "make key public");
             ScopeExit restore(
                 [&]() noexcept
                 {
                     const int restored = fchmodat(directory.get(), "user.key", 0600, 0);
                     (void)restored;
                 });
             rejects([&] { user_identity_files(caller); });
             need(fchmodat(directory.get(), "user.key", 0600, 0) == 0 && fchmod(directory.get(), 0770) == 0,
                  "make directory writable");
             ScopeExit restore_directory([&]() noexcept { fchmod(directory.get(), 0700); });
             rejects([&] { user_identity_files(caller); });
         });
    test("empty oversized malformed and encrypted PEM keys fail without prompts",
         [&]
         {
             ScopeExit restore(
                 [&]() noexcept
                 {
                     try
                     {
                         write("user.key", private_key);
                     }
                     catch (...)
                     {
                     }
                 });
             const Fd file(openat(directory.get(), "user.key", O_WRONLY | O_TRUNC));
             rejects([&] { user_identity_files(caller); });
             need(ftruncate(file.get(), MAX_BLOB + 1) == 0, "oversized key fixture");
             rejects([&] { user_identity_files(caller); });
             need(ftruncate(file.get(), 0) == 0, "truncate key fixture");
             write_all(file.get(), byte_view("INVALID PRIVATE KEY"));
             rejects([&] { load_user_identity(user_identity_files(caller)); });
             Bio encrypted(BIO_new(BIO_s_mem()));
             unsigned char passphrase[] = "OFFLINE TEST ONLY";
             sslneed(encrypted && PEM_write_bio_PrivateKey(encrypted.get(),
                                                           key,
                                                           EVP_aes_256_cbc(),
                                                           passphrase,
                                                           sizeof(passphrase) - 1,
                                                           nullptr,
                                                           nullptr) == 1,
                     "encrypted PEM fixture");
             write("user.key", encrypted);
             rejects([&] { load_user_identity(user_identity_files(caller)); });
         });
    test("home certificate accepts ordinary validity and a smart-card profile without enrollment template",
         [&]
         {
             Cert certificate(X509_dup(leaf));
             remove_ext(certificate.get(), TEMPLATE_OID);
             remove_ext(certificate.get(), "2.5.29.37");
             set_ext_conf(certificate.get(), NID_ext_key_usage, SMARTCARD_OID);
             need(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 365 * 86400),
                  "ordinary validity fixture");
             need(validate_leaf(certificate.get(), key, map, home_cfg) > time(nullptr),
                  "home certificate rejected ordinary profile");
             rejects([&] { validate_leaf(certificate.get(), key, map, cfg); });
         });
    test("home certificate may omit basicConstraints as stock AD CS end-entity templates do",
         [&]
         {
             Cert certificate(X509_dup(leaf));
             remove_ext(certificate.get(), "2.5.29.19");
             need(validate_leaf(certificate.get(), key, map, home_cfg) > time(nullptr),
                  "home certificate without basicConstraints rejected");
             const Config key_trust = with_source(cfg, CertificateSource::KeyTrust);
             rejects([&] { validate_leaf(certificate.get(), key, map, cfg); });
             rejects([&] { validate_leaf(certificate.get(), key, map, key_trust); });
         });
    test("home certificate retains logon identity usage and expiry checks",
         [&]
         {
             const auto reject = [&](auto mutation)
             {
                 Cert certificate(X509_dup(leaf));
                 mutation(certificate.get());
                 rejects([&] { validate_leaf(certificate.get(), key, map, home_cfg); });
             };
             reject([](X509 *c) { X509_gmtime_adj(X509_getm_notAfter(c), -1); });
             reject([](X509 *c) { X509_gmtime_adj(X509_getm_notBefore(c), 60); });
             reject([](X509 *c) { remove_ext(c, "2.5.29.15"); });
             reject([](X509 *c) { remove_ext(c, "2.5.29.37"); });
             reject([](X509 *c) { remove_ext(c, "2.5.29.17"); });
             reject(
                 [](X509 *c)
                 {
                     remove_ext(c, "2.5.29.19");
                     set_ext_conf(c, NID_basic_constraints, "critical,CA:TRUE");
                 });
             reject(
                 [](X509 *c)
                 {
                     remove_ext(c, "2.5.29.19");
                     set_ext_conf(c, NID_basic_constraints, "critical,CA:FALSE,pathlen:0");
                 });

             // Only a truly absent basicConstraints is tolerated: not a duplicate, nor one that cannot be
             // decoded (here a NULL where the SEQUENCE belongs).
             reject([](X509 *c) { set_ext_conf(c, NID_basic_constraints, "critical,CA:FALSE"); });
             reject(
                 [](X509 *c)
                 {
                     remove_ext(c, "2.5.29.19");
                     add_ext(c, raw_extension("2.5.29.19", Bytes{0x05, 0x00}));
                 });
             reject(
                 [](X509 *c)
                 {
                     remove_ext(c, "2.5.29.37");
                     set_ext_conf(c, NID_ext_key_usage, "clientAuth");
                 });
         });
}

// The enrollment request, its enrollment-agent wrapping and the CES response, with the leaf checks they feed.
static void enrollment_tests(
    const Config &cfg, const Mapping &map, EVP_PKEY *key, EVP_PKEY *other, X509_REQ *req, X509 *leaf)
{
    const Cert agent = fixture(other);

    test("base64 round trips and malformed input rejection",
         []
         {
             for (size_t n = 1; n < 513; ++n)
             {
                 Bytes b(n);
                 for (size_t i = 0; i < n; ++i)
                     b[i] = static_cast<unsigned char>(i);
                 need(unbase64(base64(b)) == b, "roundtrip");
             }
             rejects([] { unbase64("a==="); });
             rejects([] { unbase64("AA!!"); });
         });

    test("CSR self signature and requested extensions",
         [&]
         {
             sslneed(X509_REQ_verify(req, key) == 1, "CSR signature");
             need(certificate_upn(leaf) == "alice@domain.local", "UPN encoding");
             need(certificate_template(leaf) == cfg.template_oid, "template encoding");
             need(has_eku(leaf, SMARTCARD_OID) && has_eku(leaf, CLIENT_AUTH_OID) &&
                      has_eku(leaf, PKINIT_CLIENT_OID),
                  "three requested EKUs");
         });

    Bytes wrapped = wrap_eobo(req, agent.get(), other, "DOMAIN\\alice");

    test("EOBO CMS signature and encapsulated PKCS10",
         [&]
         {
             const unsigned char *p = wrapped.data();
             Cms cms(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(wrapped.size())));
             sslneed(cms && p == wrapped.data() + wrapped.size(), "CMS decode");
             need(objtext(CMS_get0_eContentType(cms.get())) == "1.2.840.113549.1.7.1", "CMS content type");

             Bio out(BIO_new(BIO_s_mem()));
             sslneed(out && CMS_verify(cms.get(),
                                       nullptr,
                                       nullptr,
                                       nullptr,
                                       out.get(),
                                       CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY) == 1,
                     "CMS verify signature");
             need(biobytes(out.get()) == request_der(req), "encapsulated CSR differs");
         });

    test("EOBO requestername is a signed BMP pair",
         [&]
         {
             const unsigned char *p = wrapped.data();
             Cms cms(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(wrapped.size())));
             auto signers = CMS_get0_SignerInfos(cms.get());
             need(sk_CMS_SignerInfo_num(signers) == 1, "signer count");
             auto si = sk_CMS_SignerInfo_value(signers, 0);
             Obj oid(OBJ_txt2obj(ENROLL_PAIR_OID, 1));
             int i = CMS_signed_get_attr_by_OBJ(si, oid.get(), -1);
             need(i >= 0, "signed requestername missing");

             X509_ATTRIBUTE *a = CMS_signed_get_attr(si, i);
             need(X509_ATTRIBUTE_count(a) == 1, "requester pair count");
             ASN1_TYPE *v = X509_ATTRIBUTE_get0_type(a, 0);
             need(v->type == V_ASN1_SEQUENCE, "requestername ASN.1 type");
             Bytes actual(ASN1_STRING_get0_data(v->value.sequence),
                          ASN1_STRING_get0_data(v->value.sequence) + ASN1_STRING_length(v->value.sequence));
             need(actual == der(0x30, join(bmp("requestername"), bmp("DOMAIN\\alice"))),
                  "requestername encoding differs");
         });

    test("valid pinned UPN template and lifetime accepted",
         [&] { need(validate_leaf(leaf, key, map, cfg) > time(nullptr), "leaf validation"); });

    test("valid leaf without SID extension accepted",
         [&]
         {
             Cert c(X509_dup(leaf));
             remove_ext(c.get(), SID_OID);
             need(validate_leaf(c.get(), key, map, cfg) > time(nullptr), "leaf validation without SID");
         });

    test("wrong UPN rejected",
         [&]
         {
             Mapping bad = map;
             bad.name = "bob";
             bad.upn = "bob@domain.local";
             rejects([&] { validate_leaf(leaf, key, bad, cfg); });
         });

    test("wrong key rejected", [&] { rejects([&] { validate_leaf(leaf, other, map, cfg); }); });

    test("wrong template rejected",
         [&]
         {
             Config bad = cfg;
             bad.template_oid += ".2";
             rejects([&] { validate_leaf(leaf, key, map, bad); });
         });

    auto reject_leaf = [&](auto &&mutator)
    {
        Cert c(X509_dup(leaf));
        mutator(c.get());
        rejects([&] { validate_leaf(c.get(), key, map, cfg); });
    };

    test("missing EKU rejected", [&] { reject_leaf([](X509 *c) { remove_ext(c, "2.5.29.37"); }); });

    test("missing digitalSignature key usage rejected",
         [&] { reject_leaf([](X509 *c) { remove_ext(c, "2.5.29.15"); }); });

    test("long lived certificate rejected",
         [&] { reject_leaf([](X509 *c) { X509_gmtime_adj(X509_getm_notAfter(c), 86400); }); });

    test("expired certificate rejected",
         [&] { reject_leaf([](X509 *c) { X509_gmtime_adj(X509_getm_notAfter(c), -1); }); });

    test("not yet valid certificate rejected",
         [&] { reject_leaf([](X509 *c) { X509_gmtime_adj(X509_getm_notBefore(c), 60); }); });

    test("WSTEP request namespace token and payload",
         [&]
         {
             auto xml = soap_request(cfg, wrapped);
             Owned<xmlDoc, xmlFreeDoc> doc(xmlReadMemory(
                 xml.data(), static_cast<int>(xml.size()), "test.xml", nullptr, XML_PARSE_NONET));
             need(doc != nullptr, "request XML");
             need(node_text(one(doc.get(), "/s:Envelope/s:Body/t:RequestSecurityToken/t:TokenType")) ==
                      "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
                  "wrong WS-Trust token profile");
             need(unbase64(node_text(
                      one(doc.get(), "/s:Envelope/s:Body/t:RequestSecurityToken/o:BinarySecurityToken"))) ==
                      wrapped,
                  "SOAP CMS differs");
         });

    test("X509 WSTEP response accepted",
         [&]
         {
             Cert got = parse_response(response_xml(to_der(leaf, i2d_X509, "fixture certificate")), key);
             need(X509_cmp(got.get(), leaf) == 0, "returned certificate differs");
         });

    test("CMS WSTEP response selects correct leaf",
         [&]
         {
             Cms cms(CMS_sign(nullptr, nullptr, nullptr, nullptr, CMS_BINARY | CMS_PARTIAL));
             sslneed(cms && CMS_add1_cert(cms.get(), agent.get()) == 1 && CMS_add1_cert(cms.get(), leaf) == 1,
                     "fixture CMS certificate set");
             const Bytes b = to_der(cms.get(), i2d_CMS_ContentInfo, "fixture CMS");
             Cert got = parse_response(response_xml(b, std::string(SECURITY_NS) + "#PKCS7"), key);
             need(X509_cmp(got.get(), leaf) == 0, "CMS selected wrong certificate");
         });

    test("SOAP fault rejected",
         [&]
         {
             std::string xml =
                 std::string("<s:Envelope xmlns:s=\"") + SOAP_NS +
                 "\"><s:Body><s:Fault><s:Reason>Denied</s:Reason></s:Fault></s:Body></s:Envelope>";
             rejects([&] { parse_response(xml, key); });
         });

    test("DTD and external entity rejected",
         [&]
         {
             rejects(
                 [&] {
                     parse_response("<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///etc/passwd'>]><x>&a;</x>", key);
                 });
         });

    test("missing certificate/pending response rejected",
         [&]
         {
             rejects(
                 [&] {
                     parse_response(
                         std::string("<s:Envelope xmlns:s=\"") + SOAP_NS + "\"><s:Body/></s:Envelope>", key);
                 });
         });

    test("oversized response rejected",
         [&] { rejects([&] { parse_response(std::string(2 * MAX_BLOB + 1, 'x'), key); }); });
}

// Sealed memory files and the FILE cache encoding that MIT Kerberos must read back.
static void cache_tests()
{
    test("sealed memfd cannot be modified",
         []
         {
             Bytes input{1, 2, 3};
             Fd fd = memory_file("test-only", input);
             need(read_all(fd.get()) == input, "memfd contents");
             errno = 0;
             need(write(fd.get(), "x", 1) == -1 && errno == EPERM, "memfd remained writable");
         });

    test("FILE v4 cache parsed by MIT Kerberos with RAII ownership",
         []
         {
             KrbContext context;
             need(krb5_init_secure_context(out(context)) == 0, "test krb5 context");
             const auto ctx = context.get();
             const auto client = parse_principal(ctx, "alice@DOMAIN.LOCAL"),
                        server = tgs_principal(ctx, "DOMAIN.LOCAL");
             KrbPrincipal principal(nullptr, {ctx});
             auto cc = krb_owner<std::remove_pointer_t<krb5_ccache>, krb5_cc_close>(ctx);
             krb5_creds output{};
             ScopeExit free_output([&]() noexcept { krb5_free_cred_contents(ctx, &output); });
             std::array<unsigned char, 32> keydata{};
             char ticket[] = "NOT-A-REAL-TICKET";
             const auto now = static_cast<krb5_timestamp>(time(nullptr));
             krb5_creds input = make_test_creds(client.get(), server.get(), keydata, now);
             input.ticket.data = ticket;
             input.ticket.length = sizeof(ticket) - 1;

             char filename[] = "/tmp/craft-test-XXXXXX";
             Fd file(mkstemp(filename));
             sysneed(file.get() >= 0, "test cache file");
             ScopeExit cleanup([&]() noexcept { unlink(filename); });
             auto bytes = file_cache(ctx, input);
             ScopeExit erase([&]() noexcept { wipe(bytes); });
             write_all(file.get(), bytes);

             need(krb5_cc_resolve(ctx, (std::string("FILE:") + filename).c_str(), out(cc)) == 0,
                  "open test cache");
             need(krb5_cc_get_principal(ctx, cc.get(), out(principal)) == 0, "MIT reads default principal");
             need(krb5_principal_compare(ctx, principal.get(), client.get()), "default principal differs");

             krb5_cc_cursor cursor{};
             need(krb5_cc_start_seq_get(ctx, cc.get(), &cursor) == 0, "start credential iterator");
             ScopeExit close_cursor([&]() noexcept { krb5_cc_end_seq_get(ctx, cc.get(), &cursor); });
             need(krb5_cc_next_cred(ctx, cc.get(), &cursor, &output) == 0, "MIT reads credential");
             need(krb5_principal_compare(ctx, output.client, input.client) &&
                      krb5_principal_compare(ctx, output.server, input.server) &&
                      output.ticket.length == input.ticket.length &&
                      std::memcmp(output.ticket.data, input.ticket.data, input.ticket.length) == 0 &&
                      output.times.endtime == input.times.endtime && is_aes(output.keyblock.enctype),
                  "credential round trip differs");

             krb5_free_cred_contents(ctx, &output);
             output = {};
             need(krb5_cc_next_cred(ctx, cc.get(), &cursor, &output) == KRB5_CC_END, "extra credentials");
         });
}

// Key Trust: the key credential blob, its DN-Binary framing and the ephemeral certificate pair.
static void key_trust_tests(const Config &cfg, EVP_PKEY *key)
{
    test("key credential blob encodes an NGC RSA key with hash integrity",
         [&]
         {
             const Bytes device(16, 0);
             const auto now = time(nullptr);
             const Bytes blob = key_credential_blob(key, device, now);
             need(blob.size() > 8 && blob[0] == 0x00 && blob[1] == 0x02 && blob[2] == 0 && blob[3] == 0,
                  "key credential version 2 header");

             // Walk the length-identifier-value entries and index them by identifier.
             std::map<int, Bytes> entries;
             size_t header = 0, pos = 4;
             while (pos + 3 <= blob.size())
             {
                 const size_t length = blob[pos] | (static_cast<size_t>(blob[pos + 1]) << 8);
                 const int id = blob[pos + 2];
                 need(pos + 3 + length <= blob.size(), "key credential entry bounds");
                 entries[id] = Bytes(blob.begin() + pos + 3, blob.begin() + pos + 3 + length);
                 if (id == 0x02) header = pos + 3 + length; // KeyMaterial and following entries begin here
                 pos += 3 + length;
             }
             need(pos == blob.size(), "key credential has trailing bytes");
             for (int id : {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09})
                 need(entries.contains(id), "key credential missing a required entry");
             need(entries[0x04] == Bytes{0x01} && entries[0x05] == Bytes{0x00},
                  "NGC key usage and AD source");
             need(entries[0x06] == device, "device identifier");
             need(entries[0x07] == Bytes{0x01, 0x02},
                  "software key must record single-credential provisioning");
             need(entries[0x01] == sha256(entries[0x03]), "KeyID is SHA-256 of the key material");
             need(entries[0x02] == sha256(ByteView(blob).subspan(header)),
                  "KeyHash covers subsequent entries");
             need(entries[0x03].size() > 8 &&
                      std::string(entries[0x03].begin(), entries[0x03].begin() + 4) == "RSA1",
                  "key material is a BCRYPT_RSAPUBLIC_BLOB");
             rejects([&] { key_credential_blob(key, Bytes(15, 0), now); });
         });

    test("DN-Binary value frames the hex blob length and object DN",
         [&]
         {
             const Bytes blob{0xde, 0xad, 0xbe, 0xef};
             need(dn_binary(blob, "CN=alice,DC=domain,DC=local") ==
                      "B:8:DEADBEEF:CN=alice,DC=domain,DC=local",
                  "DN-Binary encoding");
             rejects([&] { dn_binary(blob, "bad\nDN"); });
             rejects([&] { dn_binary(blob, ""); });
         });

    test("key trust certificate pair passes logon validation without a CA chain",
         [&]
         {
             Key fresh = generate_key(cfg.key_bits);
             auto pair = make_key_trust_pair(fresh.get(), "alice", "alice@domain.local", 36000 + 3600);
             Cert &c = pair.leaf;
             Cert &ca = pair.ca;
             const Mapping kmap{.name = "alice", .upn = "alice@domain.local"};
             need(X509_NAME_cmp(X509_get_subject_name(ca.get()), X509_get_issuer_name(ca.get())) == 0,
                  "CA certificate is self-signed");
             need(X509_NAME_cmp(X509_get_issuer_name(c.get()), X509_get_subject_name(ca.get())) == 0,
                  "leaf issuer matches ephemeral CA");
             need(certificate_upn(c.get()) == "alice@domain.local", "key trust UPN SAN");
             need(has_eku(c.get(), SMARTCARD_OID) && has_eku(c.get(), PKINIT_CLIENT_OID), "key trust EKUs");
             const Config key_trust = with_source(cfg, CertificateSource::KeyTrust);
             need(validate_leaf(c.get(), fresh.get(), kmap, key_trust) > time(nullptr),
                  "key trust certificate rejected");

             // The key trust certificate must still fail the CA enrollment checks.
             rejects([&] { validate_leaf(c.get(), fresh.get(), kmap, cfg); });

             // Key trust binds to the directory-resolved UPN; a mismatch must fail.
             Mapping bad = kmap;
             bad.upn = "bob@domain.local";
             rejects([&] { validate_leaf(c.get(), fresh.get(), bad, key_trust); });
         });
}

// A seed corpus for the fuzzer, built from the fixtures the checks above use: one valid input per parser.
static void write_fuzz_seeds(const std::string &directory)
{
    using testing::FuzzTarget;
    const Key key = generate_key(2048);
    const std::string oid = "1.3.6.1.4.1.311.21.8.999.1";
    const Req req = make_request(key.get(), "alice@domain.local", oid, "alice");
    const Cert leaf = fixture(key.get(), req.get());
    const Bytes der = to_der(leaf.get(), i2d_X509, "seed certificate");
    Bio certificate(BIO_new(BIO_s_mem())), private_key(BIO_new(BIO_s_mem()));
    sslneed(certificate && private_key && PEM_write_bio_X509(certificate.get(), leaf.get()) == 1 &&
                PEM_write_bio_PrivateKey(
                    private_key.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1,
            "seed PEM pair");
    const auto seed = [&](const char *name, FuzzTarget target, ByteView content)
    {
        const Fd file(open((directory + "/" + name).c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
        sysneed(file.get() >= 0, "create fuzz seed");
        const auto selector = static_cast<unsigned char>(target);
        write_all(file.get(), {&selector, 1});
        write_all(file.get(), content);
    };
    const std::string home = "enabled=yes\ndomain=domain.local\nrealm=DOMAIN.LOCAL\n";
    const auto fallback = home + "modes=enrollment\nnetbios=DOMAIN\ntemplate_oid=" + oid +
                          "\nces_url=https://ca.domain.local/CES\nces_auth=mtls\n"
                          "service_principal=submitter@DOMAIN.LOCAL\nkey_bits=3072\ntgt_seconds=36000\n";
    std::string options;
    for (const char *argument : {"--watch-pid", "123", "--max-duration", "21d", "--status"})
        options.append(argument).push_back('\0');
    seed("config", FuzzTarget::Config, byte_view(fallback));
    seed("home-config", FuzzTarget::HomeConfig, byte_view(home + "modes=home\n"));
    seed("response", FuzzTarget::Response, byte_view(response_xml(der)));
    seed("base64", FuzzTarget::Base64, byte_view(base64(der)));
    seed("san", FuzzTarget::Extension, extension_bytes(leaf.get(), SAN_OID));
    seed("template", FuzzTarget::Extension, extension_bytes(leaf.get(), TEMPLATE_OID));
    seed("pem-certificate", FuzzTarget::Pem, bioview(certificate.get()));
    seed("pem-key", FuzzTarget::Pem, bioview(private_key.get()));
    seed("der", FuzzTarget::Der, der);
    seed("ticket", FuzzTarget::Ticket, ticket_fixture(ENCTYPE_AES256_CTS_HMAC_SHA1_96));
    seed("options", FuzzTarget::Options, byte_view(options));
    seed("record", FuzzTarget::Record, byte_view(std::format("{:<63}\n", "1700000000 3")));
    seed("text", FuzzTarget::Text, byte_view("Linux {user} {upn} {domain}"));
    seed("stat",
         FuzzTarget::ProcStat,
         byte_view("1234 (sleep) S 1 1234 1234 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 100 1000 100\n"));
}

int main(int argc, char **argv)
{
    if (argc == 3 && std::string_view(argv[1]) == "--fuzz-seeds")
    {
        write_fuzz_seeds(argv[2]);
        return 0;
    }
    if (argc == 2 && std::string_view(argv[1]) == "--maintain-update-tests")
    {
        maintenance_update_tests();
        return failed ? 1 : 0;
    }
    if (argc == 4 && std::string_view(argv[1]) == "--collect-audit")
    {
        // Stand in for the host logging service inside the disposable test container, until killed.
        testing::AuditCollector log(argv[2], false);
        const Fd file(open(argv[3], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
        sysneed(file.get() >= 0, "open the audit collection file");
        for (;;)
            write_all(file.get(), byte_view(log.next(true) + "\n"));
    }
    if (argc == 3 && std::string_view(argv[1]) == "--maintain-fixture")
    {
        maintenance_fixture(argv[2]);
        return 0;
    }
    if (std::string_view(argv[0]) == LAUNCHER)
    {
        const Account caller = lookup_uid(getuid());
        const Fd home = caller_home(caller);
        const Fd count(openat(home.get(), ".maintain-test-issuance", O_WRONLY | O_APPEND | O_CREAT, 0600));
        write_all(count.get(), byte_view("issue\n"));
        const Fd mode(openat(home.get(), ".maintain-test-mode", O_RDONLY));
        const auto bytes = read_all(mode.get());
        const std::string value(bytes.begin(), bytes.end());
        if (value == "deny")
        {
            std::cerr << "synthetic enrollment denied\n";
            return 1;
        }
        if (value == "delay") poll(nullptr, 0, 30000);
        maintenance_fixture(value == "services" ? "services" : "healthy");
        return 0;
    }
    helper_tests();
    process_tests();

    Key key = generate_key(2048), other = generate_key(2048);
    Config cfg{.domain = "domain.local",
               .realm = "DOMAIN.LOCAL",
               .netbios = "DOMAIN",
               .template_oid = "1.3.6.1.4.1.311.21.8.999.1",
               .ces_url = "https://ca.domain.local/test/service.svc/CES",
               .service_principal = "submitter@DOMAIN.LOCAL",
               .certificate_cn = "{user}",
               .gc_url = {},
               .gc_base_dn = {},
               .kt_dc_url = {},
               .tgt = 36000,
               .renew = 604800,
               .cert_remaining = 36000,
               .cert_total = 36000,
               .interval = 60,
               .key_bits = 3072,
               .require_full_tgt_lifetime = true,
               .source = CertificateSource::Enrollment};
    Mapping map{.name = "alice", .upn = "alice@domain.local"};

    Req req =
        make_request(key.get(), "alice@domain.local", cfg.template_oid, common_name(cfg, "alice", map.upn));
    Cert leaf = fixture(key.get(), req.get());
    user_identity_tests(cfg, map, key.get(), leaf.get());
    enrollment_tests(cfg, map, key.get(), other.get(), req.get(), leaf.get());
    cache_tests();
    key_trust_tests(cfg, key.get());
    revision_tests(cfg, map, key.get(), req.get(), leaf.get());
    maintenance_tests();

    return testing::finish("No live CA/DC tests performed.");
}
