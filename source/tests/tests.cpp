// Offline tests use synthetic identities and tickets; no CA or KDC is contacted.
#define CRAFT_TEST
#include "../src/worker.cpp"
#include "../src/maintain.cpp"
using namespace craft;

static constexpr char SID_OID[] = "1.3.6.1.4.1.311.25.2";
static constexpr char OBJECTSID_OID[] = "1.3.6.1.4.1.311.25.2.1";

static int passed = 0, failed = 0;
static const krb5_creds *maintenance_grant = nullptr;
static unsigned maintenance_renewals = 0;

// Substitute only the KDC exchange while exercising real cache reads, validation and publication.
extern "C" krb5_error_code __real_krb5_get_renewed_creds(krb5_context, krb5_creds *,
                                                       krb5_principal, krb5_ccache, const char *);
extern "C" krb5_error_code __wrap_krb5_get_renewed_creds(krb5_context ctx, krb5_creds *creds,
                                                       krb5_principal client, krb5_ccache cache, const char *service)
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

static void test(const char *name, std::invocable auto &&f)
{
    try
    {
        ERR_clear_error();
        f();
        ++passed;
        std::cout << "PASS " << name << '\n';
    }
    catch (const std::exception &e)
    {
        ++failed;
        std::cerr << "FAIL " << name << ": " << e.what() << '\n';
    }
}

static void rejects(std::invocable auto &&f)
{
    bool rejected = false;
    try
    {
        f();
    }
    catch (const std::exception &)
    {
        rejected = true;
    }
    need(rejected, "operation unexpectedly accepted invalid input");
    ERR_clear_error();
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
    Ext ext(X509V3_EXT_conf_nid(nullptr, nullptr, nid, const_cast<char *>(value)));
    sslneed(ext != nullptr, "fixture extension config");
    add_ext(c, std::move(ext));
}

static Cert fixture(EVP_PKEY *key, X509_REQ *req = nullptr)
{
    Cert c(X509_new());
    sslneed(c && X509_set_version(c.get(), 2) == 1, "fixture cert");
    sslneed(ASN1_INTEGER_set(X509_get_serialNumber(c.get()), 42) == 1 && X509_set_pubkey(c.get(), key) == 1,
            "fixture identity");

    X509_NAME *name = X509_get_subject_name(c.get());
    sslneed(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char *>("OFFLINE TEST ONLY"),
                                       -1, -1, 0) == 1, "fixture name");
    sslneed(X509_set_issuer_name(c.get(), name) == 1, "fixture issuer");

    sslneed(X509_gmtime_adj(X509_getm_notBefore(c.get()), -60) &&
            X509_gmtime_adj(X509_getm_notAfter(c.get()), 600), "fixture times");

    if (req)
    {
        Extensions exts(X509_REQ_get_extensions(req));
        need(exts != nullptr, "fixture CSR extensions");
        for (int i = 0; i < sk_X509_EXTENSION_num(exts.get()); ++i)
            sslneed(X509_add_ext(c.get(), sk_X509_EXTENSION_value(exts.get(), i), -1) == 1,
                    "fixture copy extension");

        const std::string sid = "S-1-5-21-111-222-333-1101";
        Bytes v(sid.begin(), sid.end());
        add_ext(c.get(), raw_extension(SID_OID,
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

static Bytes cert_der(X509 *c)
{
    int n = i2d_X509(c, nullptr);
    sslneed(n > 0, "fixture cert length");
    Bytes out(static_cast<size_t>(n));
    auto p = out.data();
    sslneed(i2d_X509(c, &p) == n, "fixture cert encoding");
    return out;
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

static krb5_creds make_test_creds(krb5_principal client, krb5_principal server,
                                  std::span<unsigned char> keydata, krb5_timestamp now,
                                  krb5_enctype enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                                  uint32_t tgt_seconds = 36000, uint32_t renew_seconds = 604800)
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

    test("Linux account names enforce ASCII syntax and length boundaries", [] {
        for (auto name : {"alice", "alice.smith", "_", "_service-1", "a_1.b-c"})
            need(simple_name(name), "valid name rejected");
        need(simple_name(std::string(64, 'a')), "64-character name rejected");
        for (auto name : {"", "../alice", "alice@domain.local", "-alice", "1alice", "Alice", "alice ", "alice\n"})
            need(!simple_name(name), "invalid name accepted");
        need(!simple_name(std::string(65, 'a')) && !simple_name(std::string_view("alice\0x", 7)) &&
                 !simple_name(std::string_view("a\xff", 2)),
             "oversized or non-ASCII name accepted");
    });

    test("unsigned parsing boundaries and full input consumption", [] {
        need(number("0") == 0 && number("4294967295") == UINT32_MAX, "integer boundaries");
        need(number("00012") == 12 && number("60", 60) == 60, "leading zeros or cap");
        for (auto text : {"", "+1", "-1", " 1", "1 ", "1x", "4294967296", "00000000000"})
            rejects([&] { number(text); });
        rejects([] { number("61", 60); });
    });

    test("empty spans and empty sealed memory files", [] {
        const ByteView empty;
        auto file = memory_file("empty-test", empty);
        write_all(file.get(), empty);
        need(read_all(file.get(), 0).empty(), "empty read");
        need(base64(empty).empty(), "empty base64");
    });

    test("subspan transfers only the requested bytes", [] {
        const std::array<unsigned char, 5> bytes{9, 1, 2, 3, 9};
        auto file = memory_file("span-test", std::span(bytes).subspan(1, 3));
        need(read_all(file.get()) == Bytes({1, 2, 3}), "span bounds");
    });

    test("bounded reads reject oversized input", [] {
        auto file = memory_file("bounded-test", Bytes{1, 2, 3, 4});
        rejects([&] { read_all(file.get(), 3); });
        sysneed(lseek(file.get(), 0, SEEK_SET) == 0, "rewind test file");
        rejects([&] { read_all(file.get(), 0); });
    });

    test("descriptor moves transfer and release ownership", [] {
        auto first = memory_file("fd-test", Bytes{1});
        const int original = first.get();
        Fd second(std::move(first));
        need(first.get() == -1 && second.get() == original, "move construction");

        auto target = memory_file("old-fd-test", Bytes{2});
        const int old = target.get();
        target = std::move(second);
        errno = 0;
        need(second.get() == -1 && target.get() == original && fcntl(old, F_GETFD) == -1 && errno == EBADF,
             "move assignment must close previous fd");

        Fd adopted(target.release());
        need(target.get() == -1 && read_all(adopted.get()) == Bytes{1}, "release ownership");
    });

    test("scope cleanup runs on normal and exceptional exit", [] {
        int calls{};
        {
            ScopeExit cleanup([&]() noexcept { ++calls; });
        }
        rejects([&] {
            ScopeExit cleanup([&]() noexcept { ++calls; });
            fail("deliberate test exception");
        });
        need(calls == 2, "cleanup did not run exactly once per scope");
    });

    test("scope cleanup can be dismissed", [] {
        bool called = false;
        {
            ScopeExit cleanup([&]() noexcept { called = true; });
            cleanup.release();
        }
        need(!called, "dismissed cleanup ran");
    });

    test("secret buffers are erased through mutable spans", [] {
        Bytes bytes{1, 2, 3, 4};
        wipe(std::span(bytes).subspan(1, 2));
        need(bytes == Bytes({1, 0, 0, 4}), "subspan wipe");
        wipe(bytes);
        wipe({});
        need(std::ranges::all_of(bytes, [](auto byte) { return byte == 0; }), "complete wipe");
    });

    const std::string valid =
        "enabled=yes\ndomain=domain.local\nrealm=DOMAIN.LOCAL\nnetbios=DOMAIN\n"
        "template_oid=1.3.6.1.4.1.311.21.8.999.1\nces_url=https://ca.domain.local/CES\nces_auth=mtls\n"
        "service_principal=submitter@DOMAIN.LOCAL\n";

    test("configuration defaults and explicit limits", [&] {
        const auto defaults = parse_config(valid);
        need(defaults.tgt == 36000 && defaults.renew == 604800 && defaults.cert_remaining == 36000 &&
                 defaults.cert_total == 36000 && defaults.require_full_tgt_lifetime &&
                 defaults.certificate_cn == "{user}" && defaults.interval == 60 &&
                 defaults.gc_url == "ldap://domain.local:3268" &&
                 defaults.gc_base_dn == "DC=domain,DC=local",
             "default policy changed");

        const auto explicit_limits = parse_config(
            valid + "tgt_seconds=120\nrenew_seconds=240\ncert_remaining_max_seconds=300\ncert_total_max_seconds="
                    "600\nminimum_interval_seconds=90\ngc_url=ldap://"
                    "gc.custom:3268\ngc_base_dn=DC=custom,DC=local\n");
        need(explicit_limits.tgt == 120 && explicit_limits.renew == 240 &&
                 explicit_limits.cert_remaining == 300 &&
                 explicit_limits.cert_total == 600 && explicit_limits.interval == 90 &&
                 explicit_limits.gc_url == "ldap://gc.custom:3268" &&
                 explicit_limits.gc_base_dn == "DC=custom,DC=local",
             "limits not parsed");

        need(parse_config(valid + "renew_seconds=0\n").renew == 0, "renew=0 not accepted");
    });

    test("configuration parses editable CN and explicit shorter-ticket consent", [&] {
        const auto c = parse_config(valid + "certificate_cn=Linux {user}\nrequire_full_tgt_lifetime=no\n");
        need(c.certificate_cn == "Linux {user}" && !c.require_full_tgt_lifetime,
             "new configuration controls not parsed");
        rejects([&] { parse_config(valid + "require_full_tgt_lifetime=maybe\n"); });
    });

    test("configuration rejects disabled missing unknown and duplicate settings", [&] {
        rejects([&] { parse_config(valid + "enabled=yes\n"); });
        rejects([&] { parse_config(valid + "unknown=yes\n"); });
        rejects([&] { parse_config(valid + "service_principal=\n"); });
        rejects([&] { parse_config(std::string_view(valid).substr(12)); });
        auto disabled = valid;
        disabled.replace(8, 3, "no");
        rejects([&] { parse_config(disabled); });
    });

    test("configuration preserves lifetime rate and transport restrictions", [&] {
        for (auto setting : {"tgt_seconds=59\n",
                             "tgt_seconds=604801\n",
                             "renew_seconds=604801\n",
                             "renew_seconds=30\n",
                             "minimum_interval_seconds=29\n",
                             "cert_remaining_max_seconds=59\n",
                             "cert_total_max_seconds=600\n"})
            rejects([&] { parse_config(valid + setting); });

        auto negotiate = valid;
        negotiate.replace(negotiate.find("mtls"), 4, "negotiate");
        need(parse_config(negotiate).ces_auth == "negotiate", "configured Negotiate rejected");
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

    test("configuration rejects malformed DNS labels in domains and realms", [&] {
        for (auto domain : {"-domain.local", "domain-.local", "domain..local", ".domain.local", "domain.local."})
        {
            auto config = valid;
            config.replace(config.find("domain.local"), 12, domain);
            rejects([&] { parse_config(config); });
        }
        for (auto realm : {"-DOMAIN.LOCAL", "DOMAIN-.LOCAL", "DOMAIN..LOCAL", ".DOMAIN.LOCAL", "DOMAIN.LOCAL."})
        {
            auto config = valid;
            config.replace(config.find("DOMAIN.LOCAL"), 12, realm);
            rejects([&] { parse_config(config); });
        }
        for (auto domain : {std::string(64, 'a') + ".local", std::string("Domain.local"),
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

    test("domain_to_dn formats DNS domain to LDAP distinguished name", [&] {
        need(domain_to_dn("craft.lab") == "DC=craft,DC=lab", "domain DN conversion");
        need(domain_to_dn("sub.corp.example.com") == "DC=sub,DC=corp,DC=example,DC=com", "nested domain DN");
        need(domain_to_dn("domain") == "DC=domain", "single part domain DN");
    });

    test("base64 strips permitted whitespace and rejects embedded padding", [] {
        need(unbase64(" A Q\tI\rD\n") == Bytes({1, 2, 3}), "whitespace handling");
        for (auto text : {"", "    ", "A=AA", "AAAA====", "A", "AA\v="})
            rejects([&] { unbase64(text); });
    });

    test("large base64 payloads decode within the response size bound", [] {
        Bytes payload(MAX_BLOB, 0xa5);
        need(unbase64(base64(payload)) == payload, "large base64 roundtrip");
        rejects([] { unbase64(std::string(2 * MAX_BLOB + 1, 'A')); });
    });

    test("DER length boundaries preserve span payloads", [] {
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

    test("HTTP receive callback rejects overflow and capacity exhaustion", [] {
        char byte = 'x';
        std::string response;
        need(receive(&byte, SIZE_MAX, 2, &response) == 0 && response.empty(),
             "callback multiplication overflow");
        response.resize(2 * MAX_BLOB, 'x');
        need(receive(&byte, 1, 1, &response) == 0 && response.size() == 2 * MAX_BLOB,
             "callback size limit");
    });
}

static Bytes ticket_fixture(krb5_enctype enctype)
{
    auto text = [](std::string_view value) { return der(0x1b, byte_view(value)); };
    const auto version = der(0xa0, der(0x02, Bytes{5}));
    const auto realm = der(0xa1, text("DOMAIN.LOCAL"));
    const auto names = der(0x30, join(text("krbtgt"), text("DOMAIN.LOCAL")));
    const auto principal = der(0xa2, der(0x30, join(der(0xa0, der(0x02, Bytes{2})), der(0xa1, names))));
    const auto enc = der(0xa3, der(0x30, join(der(0xa0, der(0x02, Bytes{static_cast<unsigned char>(enctype)})),
                                              der(0xa2, der(0x04, byte_view("NOT-A-REAL-TICKET"))))));
    return der(0x61, der(0x30, join(join(join(version, realm), principal), enc)));
}

static void revision_tests(const Config &cfg, const Mapping &map, EVP_PKEY *key, X509_REQ *req, X509 *leaf)
{
    auto reject_leaf = [&](auto &&mutator) {
        Cert c(X509_dup(leaf));
        mutator(c.get());
        rejects([&] { validate_leaf(c.get(), key, map, cfg); });
    };

    test("ten-hour certificate accepted independently of renewal request", [&] {
        Cert c(X509_dup(leaf));
        const auto now = time(nullptr);
        sslneed(ASN1_TIME_set(X509_getm_notBefore(c.get()), now - 60) &&
                    ASN1_TIME_set(X509_getm_notAfter(c.get()), now + 35940),
                "ten-hour fixture validity");
        need(validate_leaf(c.get(), key, map, cfg) > time(nullptr), "10h certificate rejected");
    });

    test("certificate total validity cannot exceed ten hours", [&] {
        reject_leaf([](X509 *c) {
            X509_gmtime_adj(X509_getm_notBefore(c), -601);
            X509_gmtime_adj(X509_getm_notAfter(c), 36000);
        });
    });

    test("missing non-CA constraint rejected", [&] {
        reject_leaf([](X509 *c) { remove_ext(c, "2.5.29.19"); });
    });

    test("PKINIT-specific client EKU is required", [&] {
        reject_leaf([](X509 *c) {
            remove_ext(c, "2.5.29.37");
            set_ext_conf(c, NID_ext_key_usage, "clientAuth,1.3.6.1.4.1.311.20.2.2");
        });
    });

    test("CA signing key usage rejected", [&] {
        reject_leaf([](X509 *c) {
            remove_ext(c, "2.5.29.15");
            set_ext_conf(c, NID_key_usage, "critical,digitalSignature,keyCertSign");
        });
    });

    test("custom CN placeholders do not change the identity", [&] {
        Config custom = cfg;
        custom.certificate_cn = "Linux logon - {user} - {domain}";
        need(common_name(custom, "alice", map.upn) == "Linux logon - alice - domain.local", "CN expansion");
        auto csr = make_request(key, "alice@domain.local", cfg.template_oid, common_name(custom, "alice", map.upn));
        std::array<char, 128> actual{};
        X509_NAME_get_text_by_NID(X509_REQ_get_subject_name(csr.get()), NID_commonName, actual.data(), actual.size());
        need(std::string(actual.data()) == common_name(custom, "alice", map.upn), "CSR CN differs");

        custom.certificate_cn = "{upn}";
        need(common_name(custom, "alice", map.upn) == "alice@domain.local", "UPN placeholder");
    });

    test("CN UPN placeholder preserves the actual directory identity literally", [&] {
        auto custom = cfg;
        custom.certificate_cn = "{upn}";
        need(common_name(custom, "alice", "alice$&@alt.example") == "alice$&@alt.example",
             "directory UPN replaced or interpreted as replacement syntax");
    });

    test("CN rejects unknown placeholders controls and excessive length", [&] {
        for (const auto &pattern : {std::string("{uid}"), std::string("bad\nCN"), std::string(65, 'a'), std::string{}})
        {
            Config custom = cfg;
            custom.certificate_cn = pattern;
            rejects([&] { common_name(custom, "alice", map.upn); });
        }
    });

    test("CSR contains no enrollee-supplied SID", [&] {
        Extensions exts(X509_REQ_get_extensions(req));
        for (int i = 0; i < sk_X509_EXTENSION_num(exts.get()); ++i)
            need(objtext(X509_EXTENSION_get_object(sk_X509_EXTENSION_value(exts.get(), i))) != SID_OID,
                 "SID must be supplied by the CA");
    });

    test("template extension accepts an OID with optional unsigned versions", [&] {
        for (const auto &versions : {Bytes{}, der(0x02, Bytes{0}),
                                     join(der(0x02, Bytes{0, 0xff, 0xff, 0xff, 0xff}), der(0x02, Bytes{1}))})
        {
            Cert c(X509_dup(leaf));
            remove_ext(c.get(), TEMPLATE_OID);
            add_ext(c.get(), raw_extension(TEMPLATE_OID, der(0x30, join(oid_der(cfg.template_oid), versions))));
            need(certificate_template(c.get()) == cfg.template_oid, "valid template version rejected");
        }
    });

    test("template extension rejects malformed or excessive version fields", [&] {
        for (const auto &versions : {der(0x0c, byte_view("1")), der(0x02, Bytes{0xff}),
                                     der(0x02, Bytes{1, 0, 0, 0, 0}),
                                     join(der(0x02, Bytes{1}), join(der(0x02, Bytes{2}), der(0x02, Bytes{3})))})
        {
            Cert c(X509_dup(leaf));
            remove_ext(c.get(), TEMPLATE_OID);
            add_ext(c.get(), raw_extension(TEMPLATE_OID, der(0x30, join(oid_der(cfg.template_oid), versions))));
            rejects([&] { certificate_template(c.get()); });
        }
    });

    test("RAII C-output adoption and cleanup survive exceptions", [] {
        int freed = 0;
        const auto deleter = [&freed](int *p) noexcept {
            if (p) { ++freed; delete p; }
        };
        using Pointer = std::unique_ptr<int, decltype(deleter)>;

        rejects([&] {
            Pointer pointer(nullptr, deleter);
            const auto allocates_then_fails = [](int **target) {
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
    auto client = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
    auto server = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
    need(krb5_parse_name(ctx, "alice@DOMAIN.LOCAL", out(client)) == 0, "revision client");
    need(krb5_parse_name(ctx, "krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL", out(server)) == 0, "revision server");
    std::array<unsigned char, 32> keydata{};
    const auto now = static_cast<krb5_timestamp>(time(nullptr));
    krb5_creds creds = make_test_creds(client.get(), server.get(), keydata, now);

    auto reject_tgt = [&](auto &&mutator) {
        auto c = creds;
        mutator(c);
        rejects([&] { validate_tgt(ctx, cfg, c, client.get(), server.get(), now, now); });
    };

    test("ten-hour AES256 ticket with seven-day renewal accepted", [&] {
        validate_tgt(ctx, cfg, creds, client.get(), server.get(), now, now);
    });

    test("ten-hour AES128 ticket with seven-day renewal accepted", [&] {
        auto c = creds;
        c.keyblock.enctype = ENCTYPE_AES128_CTS_HMAC_SHA1_96;
        c.keyblock.length = 16;
        validate_tgt(ctx, cfg, c, client.get(), server.get(), now, now);
    });

    test("DC-shortened four-hour ticket rejected in strict mode", [&] {
        reject_tgt([&](auto &c) { c.times.endtime = now + 14400; });
    });

    test("explicit nonstrict mode accepts capped lifetime with warning", [&] {
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

    test("DC-shortened renewable lifetime rejected in strict mode", [&] {
        reject_tgt([&](auto &c) { c.times.renew_till = now + 86400; });
    });

    test("explicit nonstrict mode accepts capped renewable lifetime with warning", [&] {
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

    test("forwardable and noninitial user tickets rejected", [&] {
        for (auto flag : {TKT_FLG_FORWARDABLE, TKT_FLG_FORWARDED, TKT_FLG_PROXIABLE,
                          TKT_FLG_PROXY, TKT_FLG_MAY_POSTDATE, TKT_FLG_INVALID})
            reject_tgt([&](auto &c) { c.ticket_flags |= flag; });
        reject_tgt([&](auto &c) { c.ticket_flags &= ~TKT_FLG_INITIAL; });
    });

    test("excessive expired and unrequested renewable lifetimes rejected", [&] {
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

        rejects([&] {
            auto bad = c_no_renew;
            bad.ticket_flags |= TKT_FLG_RENEWABLE;
            validate_tgt(ctx, no_renew, bad, client.get(), server.get(), now, now);
        });
        rejects([&] {
            auto bad = c_no_renew;
            bad.times.renew_till = now + 604800;
            validate_tgt(ctx, no_renew, bad, client.get(), server.get(), now, now);
        });
    });

    test("RC4 and incorrect AES key lengths rejected", [&] {
        reject_tgt([&](auto &c) { c.keyblock.enctype = ENCTYPE_ARCFOUR_HMAC; });
        reject_tgt([&](auto &c) { c.keyblock.length = 16; });
    });

    test("unexpected user or service principal rejected", [&] {
        reject_tgt([&](auto &c) { c.client = server.get(); });
        reject_tgt([&](auto &c) { c.server = client.get(); });
    });

    test("outer TGT envelope accepts AES128 and AES256", [&] {
        for (auto type : AES_TYPES)
        {
            auto encoded = ticket_fixture(type);
            krb5_data data{.magic = 0,
                           .length = static_cast<unsigned>(encoded.size()),
                           .data = reinterpret_cast<char *>(encoded.data())};
            need(ticket_enctype(ctx, data) == type, "outer enctype differs");
        }
    });

    test("outer TGT envelope rejects RC4 and malformed tickets", [&] {
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
    test("maintenance options require an explicit job and bounded durations", [] {
        auto parse = [](std::initializer_list<const char *> values)
        {
            std::vector<char *> args;
            for (auto value : values) args.push_back(const_cast<char *>(value));
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
    auto client = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
    auto server = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
    need(krb5_parse_name(ctx, "alice@DOMAIN.LOCAL", out(client)) == 0 &&
             krb5_parse_name(ctx, "krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL", out(server)) == 0,
         "maintenance fixture principals");
    std::array<unsigned char, 32> key{};
    auto ticket = ticket_fixture(ENCTYPE_AES256_CTS_HMAC_SHA1_96);
    auto tgt = make_test_creds(client.get(), server.get(), key, now);
    tgt.ticket = {.magic = 0, .length = static_cast<unsigned int>(ticket.size()),
                  .data = reinterpret_cast<char *>(ticket.data())};

    test("maintenance schedules renewal and weekly enrollment from actual deadlines", [&] {
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
        need(schedule(&nonrenewable, now).action == Action::Idle, "healthy nonrenewable ticket re-enrolled");
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
    test("renewal accepts original authentication time and an unchanged absolute renewal window", [&] {
        validate_renewed_tgt(ctx, old, renewed, now);
        auto shorter = renewed;
        shorter.times.renew_till -= 3600;
        validate_renewed_tgt(ctx, old, shorter, now);
    });
    test("renewal rejects new windows, changed identities, excessive grants and prohibited flags", [&] {
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
    ScopeExit cleanup([&]() noexcept
    {
        for (auto name : {CACHE_NAME, CACHE_LOCK, "outside", "source", "lock", "target"})
            unlink((caller.home + "/" + name).c_str());
        rmdir(directory);
    });
    test("atomic cache publication retains private ownership and leaves the old inode readable", [&] {
        auto bytes = file_cache(ctx, old);
        publish_cache(caller, bytes);
        Fd previous(open((caller.home + "/" + CACHE_NAME).c_str(), O_RDONLY | O_CLOEXEC));
        auto fresh = file_cache(ctx, renewed);
        publish_cache(caller, fresh);
        const Fd current(open((caller.home + "/" + CACHE_NAME).c_str(), O_RDONLY | O_CLOEXEC));
        struct stat st{};
        need(fstat(current.get(), &st) == 0 && st.st_uid == caller.uid && (st.st_mode & 0777) == 0600,
             "cache publication permissions");
        need(read_all(previous.get()) == bytes && read_all(current.get()) == fresh, "publication lost an inode");
        wipe(bytes);
        wipe(fresh);
        need(chmod(directory, 0777) == 0, "make unsafe home fixture");
        rejects([&] { caller_home(caller); });
        need(chmod(directory, 0700) == 0, "restore home permissions");
    });
    test("cache locking refuses symlinks and serializes different processes", [&] {
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
        ScopeExit reap([&]() noexcept { kill(child, SIGKILL); waitpid(child, nullptr, 0); });
        pollfd ready{reader.get(), POLLIN, 0};
        need(poll(&ready, 1, 100) == 0, "second process acquired held lock");
        locked = Fd();
        need(poll(&ready, 1, 2000) > 0, "second process did not acquire released lock");
        int status{};
        need(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
             "lock test child failed");
        reap.release();
    });
    test("renewed cache preserves usable service tickets and removes the old TGT and expired services", [&] {
        auto source = krb_owner<std::remove_pointer_t<krb5_ccache>, krb5_cc_close>(ctx);
        const auto filename = caller.home + "/source";
        need(krb5_cc_resolve(ctx, ("FILE:" + filename).c_str(), out(source)) == 0, "resolve source cache fixture");
        need(krb5_cc_initialize(ctx, source.get(), client.get()) == 0 &&
                 krb5_cc_store_cred(ctx, source.get(), &old) == 0, "source cache fixture");
        auto service = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
        auto expired = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
        need(krb5_parse_name(ctx, "ldap/host@DOMAIN.LOCAL", out(service)) == 0 &&
                 krb5_parse_name(ctx, "cifs/host@DOMAIN.LOCAL", out(expired)) == 0, "service fixture");
        char service_ticket[] = "SYNTHETIC SERVICE";
        auto extra = old;
        extra.server = service.get();
        extra.ticket = {.magic = 0, .length = sizeof(service_ticket) - 1, .data = service_ticket};
        need(krb5_cc_store_cred(ctx, source.get(), &extra) == 0, "store service fixture");
        extra.server = expired.get();
        extra.times.endtime = now - 1;
        need(krb5_cc_store_cred(ctx, source.get(), &extra) == 0, "store expired fixture");
        auto bytes = renewed_cache(ctx, source.get(), renewed, now);
        publish_cache(caller, bytes);
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
            else need(krb5_principal_compare(ctx, found.server, service.get()), "retained expired service");
            ++count;
        }
        need(count == 2, "renewed cache dropped or duplicated credentials");
    });
    test("pidfd observes job termination and refuses other Linux identities", [] {
        const auto child = fork();
        need(child >= 0, "watch test fork");
        if (child == 0) { poll(nullptr, 0, 2000); _exit(0); }
        ScopeExit reap([&]() noexcept { kill(child, SIGKILL); waitpid(child, nullptr, 0); });
        auto descriptor = watch_process(child, getuid());
        need(!exited(descriptor.get()), "watcher ended prematurely");
        rejects([&] { watch_process(child, getuid() + 1); });
        kill(child, SIGTERM);
        need(waitpid(child, nullptr, 0) == child && exited(descriptor.get()), "job exit was not observed");
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
    auto client = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
    auto server = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
    need(krb5_parse_name(ctx, "craft-maintain-test@DOMAIN.LOCAL", out(client)) == 0 &&
             krb5_parse_name(ctx, "krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL", out(server)) == 0, "fixture identity");
    std::array<unsigned char, 32> key{};
    const auto now = static_cast<krb5_timestamp>(time(nullptr));
    auto tgt = make_test_creds(client.get(), server.get(), key, now);
    if (mode == "renew" || mode == "nonrenewable")
    {
        tgt.times.authtime = tgt.times.starttime = now - 32400;
        tgt.times.endtime = now + 3600;
        tgt.times.renew_till = tgt.times.authtime + 604800;
        if (mode == "nonrenewable") { tgt.ticket_flags &= ~TKT_FLG_RENEWABLE; tgt.times.renew_till = 0; }
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
    auto encoded = ticket_fixture(ENCTYPE_AES256_CTS_HMAC_SHA1_96);
    tgt.ticket = {.magic = 0, .length = static_cast<unsigned int>(encoded.size()),
                  .data = reinterpret_cast<char *>(encoded.data())};
    auto bytes = file_cache(ctx, tgt);
    publish_cache(caller, bytes);
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
    auto client = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
    auto server = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
    need(krb5_cc_resolve(ctx, ("FILE:" + caller.home + "/" + CACHE_NAME).c_str(), out(cache)) == 0,
         "maintenance update cache");
    need(krb5_cc_get_principal(ctx, cache.get(), out(client)) == 0 &&
             krb5_parse_name(ctx, "krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL", out(server)) == 0,
         "maintenance update principals");
    krb5_creds match{}, original{};
    match.client = client.get();
    match.server = server.get();
    need(krb5_cc_retrieve_cred(ctx, cache.get(), 0, &match, &original) == 0, "read rollover fixture");
    ScopeExit cleanup([&]() noexcept { maintenance_grant = nullptr; krb5_free_cred_contents(ctx, &original); });
    auto read = [&](const char *name)
    {
        const Fd file(openat(home.get(), name, O_RDONLY | O_CLOEXEC));
        need(file.get() >= 0, "read maintenance update fixture");
        return read_all(file.get());
    };
    auto publish = [&](krb5_creds &tgt)
    {
        auto bytes = file_cache(ctx, tgt);
        publish_cache(caller, bytes);
        wipe(bytes);
    };

    test("enrollment denial and shared cooldown cannot postpone a due renewal", [&] {
        for (const char *name : {".maintain-test-issuance", ".krb5cc_craft.maintain.retry"})
            need(unlinkat(home.get(), name, 0) == 0 || errno == ENOENT, "reset enrollment state");
        const Fd mode(openat(home.get(), ".maintain-test-mode", O_WRONLY | O_CREAT | O_TRUNC, 0600));
        need(mode.get() >= 0, "deny test enrollment");
        write_all(mode.get(), byte_view("deny"));
        const auto now = static_cast<krb5_timestamp>(time(nullptr));
        auto due = original;
        due.times.starttime = now - 28800 + 30;
        due.times.endtime = now + 7200 + 30;
        publish(due);

        // An issuer failure must wake the loop by the renewal threshold without shortening shared backoff.
        Result denied;
        rejects([&] { update(caller, {}, denied); });
        need(!denied.success && denied.retry > 0 && denied.retry <= 30, "enrollment backoff delays renewal");
        const auto issuance = read(".maintain-test-issuance"), retry = read(".krb5cc_craft.maintain.retry");
        need(std::ranges::count(issuance, '\n') == 1, "enrollment denial was not exercised");
        std::istringstream retry_state(std::string(retry.begin(), retry.end()));
        int64_t next = 0;
        need(static_cast<bool>(retry_state >> next) && next >= now + 60, "shared enrollment cooldown was shortened");
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
        need(read(".maintain-test-issuance") == issuance && read(".krb5cc_craft.maintain.retry") == retry,
             "renewal bypassed or reset shared enrollment backoff");
        krb5_creds saved{};
        ScopeExit free([&]() noexcept { krb5_free_cred_contents(ctx, &saved); });
        need(krb5_cc_retrieve_cred(ctx, cache.get(), 0, &match, &saved) == 0 &&
                 saved.times.endtime == grant.times.endtime, "renewed TGT was not published");

        // A ticket already at its absolute deadline must retain enrollment backoff instead of attempting renewal.
        due.times.starttime = now - 300;
        due.times.endtime = due.times.renew_till = now + 60;
        publish(due);
        maintenance_grant = &grant;
        Result exhausted;
        rejects([&] { update(caller, {}, exhausted); });
        need(maintenance_renewals == 1 && exhausted.retry >= 45,
             "an exhausted renewal window caused renewal or busy polling");
    });
    for (const bool near_expiry : {false, true})
        test(near_expiry ? "a renewal grant already due for renewal is revisited promptly"
                        : "a shortened renewal window triggers prompt enrollment", [&] {
            for (const char *name : {".maintain-test-issuance", ".krb5cc_craft.maintain.retry"})
                need(unlinkat(home.get(), name, 0) == 0 || errno == ENOENT, "reset shortened grant state");
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
            need(refreshed.success && refreshed.end > shortened.end, "follow-up did not extend the short grant");
            if (near_expiry) need(maintenance_renewals == 2, "due renewal did not run again");
            else need(maintenance_renewals == 1 && std::ranges::count(read(".maintain-test-issuance"), '\n') == 1,
                      "shortened renewal window did not enroll once");
        });
}

int main(int argc, char **argv)
{
    if (argc == 2 && std::string_view(argv[1]) == "--maintain-update-tests")
    {
        maintenance_update_tests();
        return failed ? 1 : 0;
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
        if (value == "deny") { std::cerr << "synthetic enrollment denied\n"; return 1; }
        if (value == "delay") poll(nullptr, 0, 30000);
        maintenance_fixture("healthy");
        return 0;
    }
    helper_tests();

    Key key = generate_key(), other = generate_key();
    Config cfg{.domain = "domain.local",
               .realm = "DOMAIN.LOCAL",
               .netbios = "DOMAIN",
               .template_oid = "1.3.6.1.4.1.311.21.8.999.1",
               .ces_url = "https://ca.domain.local/test/service.svc/CES",
               .ces_auth = "mtls",
               .service_principal = "submitter@DOMAIN.LOCAL",
               .certificate_cn = "{user}",
               .gc_url = {},
               .gc_base_dn = {},
               .tgt = 36000,
               .renew = 604800,
               .cert_remaining = 36000,
               .cert_total = 36000,
               .interval = 60,
               .require_full_tgt_lifetime = true};
    Mapping map{.uid = 1001, .name = "alice", .upn = "alice@domain.local"};

    Req req = make_request(key.get(), "alice@domain.local", cfg.template_oid, common_name(cfg, "alice", map.upn));
    Cert leaf = fixture(key.get(), req.get()), agent = fixture(other.get());

    test("base64 round trips and malformed input rejection", [] {
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

    test("CSR self signature and requested extensions", [&] {
        sslneed(X509_REQ_verify(req.get(), key.get()) == 1, "CSR signature");
        need(certificate_upn(leaf.get()) == "alice@domain.local", "UPN encoding");
        need(certificate_template(leaf.get()) == cfg.template_oid, "template encoding");
        need(has_eku(leaf.get(), SMARTCARD_OID) && has_eku(leaf.get(), CLIENT_AUTH_OID) &&
                 has_eku(leaf.get(), PKINIT_CLIENT_OID),
             "three requested EKUs");
    });

    Bytes wrapped = wrap_eobo(req.get(), agent.get(), other.get(), "DOMAIN\\alice");

    test("EOBO CMS signature and encapsulated PKCS10", [&] {
        const unsigned char *p = wrapped.data();
        Cms cms(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(wrapped.size())));
        sslneed(cms && p == wrapped.data() + wrapped.size(), "CMS decode");
        need(objtext(CMS_get0_eContentType(cms.get())) == "1.2.840.113549.1.7.1", "CMS content type");

        Bio out(BIO_new(BIO_s_mem()));
        sslneed(out && CMS_verify(cms.get(), nullptr, nullptr, nullptr, out.get(),
                                  CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY) == 1,
                "CMS verify signature");
        need(biobytes(out.get()) == request_der(req.get()), "encapsulated CSR differs");
    });

    test("EOBO requestername is a signed BMP pair", [&] {
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

    test("valid pinned UPN template and lifetime accepted", [&] {
        need(validate_leaf(leaf.get(), key.get(), map, cfg) > time(nullptr), "leaf validation");
    });

    test("valid leaf without SID extension accepted", [&] {
        Cert c(X509_dup(leaf.get()));
        remove_ext(c.get(), SID_OID);
        need(validate_leaf(c.get(), key.get(), map, cfg) > time(nullptr), "leaf validation without SID");
    });

    test("wrong UPN rejected", [&] {
        Mapping bad = map;
        bad.name = "bob";
        bad.upn = "bob@domain.local";
        rejects([&] { validate_leaf(leaf.get(), key.get(), bad, cfg); });
    });

    test("wrong key rejected", [&] {
        rejects([&] { validate_leaf(leaf.get(), other.get(), map, cfg); });
    });

    test("wrong template rejected", [&] {
        Config bad = cfg;
        bad.template_oid += ".2";
        rejects([&] { validate_leaf(leaf.get(), key.get(), map, bad); });
    });

    auto reject_leaf = [&](auto &&mutator) {
        Cert c(X509_dup(leaf.get()));
        mutator(c.get());
        rejects([&] { validate_leaf(c.get(), key.get(), map, cfg); });
    };

    test("missing EKU rejected", [&] {
        reject_leaf([](X509 *c) { remove_ext(c, "2.5.29.37"); });
    });

    test("missing digitalSignature key usage rejected", [&] {
        reject_leaf([](X509 *c) { remove_ext(c, "2.5.29.15"); });
    });

    test("long lived certificate rejected", [&] {
        reject_leaf([](X509 *c) { X509_gmtime_adj(X509_getm_notAfter(c), 86400); });
    });

    test("expired certificate rejected", [&] {
        reject_leaf([](X509 *c) { X509_gmtime_adj(X509_getm_notAfter(c), -1); });
    });

    test("not yet valid certificate rejected", [&] {
        reject_leaf([](X509 *c) { X509_gmtime_adj(X509_getm_notBefore(c), 60); });
    });

    test("WSTEP request namespace token and payload", [&] {
        auto xml = soap_request(cfg, wrapped);
        Owned<xmlDoc, xmlFreeDoc> doc(xmlReadMemory(
            xml.data(), static_cast<int>(xml.size()), "test.xml", nullptr, XML_PARSE_NONET));
        need(doc != nullptr, "request XML");
        need(node_text(one(doc.get(), "/s:Envelope/s:Body/t:RequestSecurityToken/t:TokenType")) ==
                 "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
             "wrong WS-Trust token profile");
        need(unbase64(node_text(
                 one(doc.get(), "/s:Envelope/s:Body/t:RequestSecurityToken/o:BinarySecurityToken"))) == wrapped,
             "SOAP CMS differs");
    });

    test("X509 WSTEP response accepted", [&] {
        Cert got = parse_response(response_xml(cert_der(leaf.get())), key.get());
        need(X509_cmp(got.get(), leaf.get()) == 0, "returned certificate differs");
    });

    test("CMS WSTEP response selects correct leaf", [&] {
        Cms cms(CMS_sign(nullptr, nullptr, nullptr, nullptr, CMS_BINARY | CMS_PARTIAL));
        sslneed(cms && CMS_add1_cert(cms.get(), agent.get()) == 1 &&
                    CMS_add1_cert(cms.get(), leaf.get()) == 1,
                "fixture CMS certificate set");
        int n = i2d_CMS_ContentInfo(cms.get(), nullptr);
        sslneed(n > 0, "fixture CMS length");
        Bytes b(static_cast<size_t>(n));
        auto p = b.data();
        i2d_CMS_ContentInfo(cms.get(), &p);

        Cert got = parse_response(response_xml(b, std::string(SECURITY_NS) + "#PKCS7"), key.get());
        need(X509_cmp(got.get(), leaf.get()) == 0, "CMS selected wrong certificate");
    });

    test("SOAP fault rejected", [&] {
        std::string xml =
            std::string("<s:Envelope xmlns:s=\"") + SOAP_NS +
            "\"><s:Body><s:Fault><s:Reason>Denied</s:Reason></s:Fault></s:Body></s:Envelope>";
        rejects([&] { parse_response(xml, key.get()); });
    });

    test("DTD and external entity rejected", [&] {
        rejects([&] {
            parse_response("<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///etc/passwd'>]><x>&a;</x>", key.get());
        });
    });

    test("missing certificate/pending response rejected", [&] {
        rejects([&] {
            parse_response(std::string("<s:Envelope xmlns:s=\"") + SOAP_NS + "\"><s:Body/></s:Envelope>",
                           key.get());
        });
    });

    test("oversized response rejected", [&] {
        rejects([&] { parse_response(std::string(2 * MAX_BLOB + 1, 'x'), key.get()); });
    });

    test("sealed memfd cannot be modified", [] {
        Bytes input{1, 2, 3};
        Fd fd = memory_file("test-only", input);
        need(read_all(fd.get()) == input, "memfd contents");
        errno = 0;
        need(write(fd.get(), "x", 1) == -1 && errno == EPERM, "memfd remained writable");
    });

    test("FILE v4 cache parsed by MIT Kerberos with RAII ownership", [] {
        KrbContext context;
        need(krb5_init_secure_context(out(context)) == 0, "test krb5 context");
        const auto ctx = context.get();
        auto client = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
        auto server = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
        auto principal = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx);
        auto cc = krb_owner<std::remove_pointer_t<krb5_ccache>, krb5_cc_close>(ctx);
        krb5_creds output{};
        ScopeExit free_output([&]() noexcept { krb5_free_cred_contents(ctx, &output); });
        need(krb5_parse_name(ctx, "alice@DOMAIN.LOCAL", out(client)) == 0, "test client");
        need(krb5_parse_name(ctx, "krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL", out(server)) == 0, "test server");

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

    revision_tests(cfg, map, key.get(), req.get(), leaf.get());
    maintenance_tests();

    std::cout << passed << " passed; " << failed << " failed. No live CA/DC tests performed.\n";
    return failed ? 1 : 0;
}
