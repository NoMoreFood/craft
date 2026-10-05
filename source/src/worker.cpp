// Unprivileged, dedicated-account worker. The public entry point is launcher.cpp.
#include "common.hpp"
#include <sys/mman.h>
#include <sys/file.h>
#include <signal.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <curl/curl.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <krb5.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include <memory>
#include <iostream>
#include <regex>
#include <ctime>
#include <syslog.h>

#include "resources.hpp"

namespace craft
{
using Key = Owned<EVP_PKEY, EVP_PKEY_free>;
using Cert = Owned<X509, X509_free>;
using Req = Owned<X509_REQ, X509_REQ_free>;
using Bio = Owned<BIO, BIO_free>;
using Cms = Owned<CMS_ContentInfo, CMS_ContentInfo_free>;
using Obj = Owned<ASN1_OBJECT, ASN1_OBJECT_free>;
using Ext = Owned<X509_EXTENSION, X509_EXTENSION_free>;

inline void free_xml(xmlChar *value) noexcept
{
    xmlFree(value);
}
using XmlText = Owned<xmlChar, free_xml>;
inline constexpr char UPN_OID[] = "1.3.6.1.4.1.311.20.2.3";
inline constexpr char AGENT_OID[] = "1.3.6.1.4.1.311.20.2.1";
inline constexpr char PKINIT_CLIENT_OID[] = "1.3.6.1.5.2.3.4";
inline constexpr char CLIENT_AUTH_OID[] = "1.3.6.1.5.5.7.3.2";
inline constexpr char SMARTCARD_OID[] = "1.3.6.1.4.1.311.20.2.2";
inline constexpr char TEMPLATE_OID[] = "1.3.6.1.4.1.311.21.7";
inline constexpr char ENROLL_PAIR_OID[] = "1.3.6.1.4.1.311.13.2.1";

inline std::string path(std::string_view name)
{
    return std::format("{}/{}", CONFIG_DIR, name);
}

inline void sslneed(bool good, const std::string &what)
{
    if (good) return;
    unsigned long e = ERR_get_error();
    char buf[256]{};
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    fail(what + (e ? std::string(": ") + buf : ""));
}

inline std::string objtext(const ASN1_OBJECT *o)
{
    need(o != nullptr, "missing OID");
    char s[256];
    int n = OBJ_obj2txt(s, sizeof(s), o, 1);
    need(n > 0 && n < static_cast<int>(sizeof(s)), "invalid OID");
    return s;
}

struct Config
{
    std::string domain, realm, netbios, template_oid, ces_url, ces_auth, service_principal;
    std::string certificate_cn = "{user}";
    std::string gc_url, gc_base_dn;
    uint32_t tgt = 36000, renew = 604800, cert_remaining = 36000, cert_total = 36000, interval = 60;
    bool require_full_tgt_lifetime = true;
};

// Parse a strict configuration independently of privileged file access.
inline Config parse_config(std::string_view text)
{
    std::map<std::string, std::string, std::less<>> v;
    std::istringstream in{std::string(text)};
    std::string s;
    const std::set<std::string> keys = {"enabled",
                                        "domain",
                                        "realm",
                                        "netbios",
                                        "template_oid",
                                        "ces_url",
                                        "ces_auth",
                                        "service_principal",
                                        "certificate_cn",
                                        "require_full_tgt_lifetime",
                                        "tgt_seconds",
                                        "renew_seconds",
                                        "cert_remaining_max_seconds",
                                        "cert_total_max_seconds",
                                        "minimum_interval_seconds",
                                        "gc_url",
                                        "gc_base_dn"};
    while (std::getline(in, s))
    {
        s = trim(s);
        if (s.empty() || s[0] == '#') continue;
        auto p = s.find('=');
        need(p != std::string::npos, "config line needs key=value");
        std::string k = trim(s.substr(0, p)), val = trim(s.substr(p + 1));
        need(keys.contains(k) && !val.empty() && v.emplace(k, val).second,
             "unknown, empty or duplicate config key");
    }
    auto get = [&](const char *k)
    {
        auto i = v.find(k);
        need(i != v.end(), std::string("missing config key: ") + k);
        return i->second;
    };
    need(get("enabled") == "yes", "service disabled; review configuration and set enabled=yes");
    Config c{.domain = get("domain"),
             .realm = get("realm"),
             .netbios = get("netbios"),
             .template_oid = get("template_oid"),
             .ces_url = get("ces_url"),
             .ces_auth = get("ces_auth"),
             .service_principal = get("service_principal"),
             .gc_url = {},
             .gc_base_dn = {}};

    // Validate domain syntax and length limits using regex
    need(c.domain.size() < 254 && c.realm.size() < 254 && c.netbios.size() <= 15, "domain value too long");
    const static std::regex domain_re(
        R"(^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$)");
    const static std::regex realm_re(
        R"(^[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)*$)");
    const static std::regex netbios_re(R"(^[A-Z0-9_-]+$)");
    need(std::regex_match(c.domain, domain_re), "domain must be lowercase DNS syntax");
    need(std::regex_match(c.realm, realm_re), "realm must be uppercase DNS syntax");
    need(std::regex_match(c.netbios, netbios_re), "invalid NetBIOS domain");
    Obj oid(OBJ_txt2obj(c.template_oid.c_str(), 1));
    sslneed(oid != nullptr, "invalid template OID");
    need(c.ces_auth == "negotiate" || c.ces_auth == "mtls", "ces_auth must be negotiate or mtls");
    if (v.contains("gc_url")) c.gc_url = v["gc_url"];
    else c.gc_url = "ldap://" + c.domain + ":3268";
    if (v.contains("gc_base_dn")) c.gc_base_dn = v["gc_base_dn"];
    else c.gc_base_dn = domain_to_dn(c.domain);
    if (v.contains("tgt_seconds")) c.tgt = number(v["tgt_seconds"], 604800);
    if (v.contains("renew_seconds")) c.renew = number(v["renew_seconds"], 604800);
    if (v.contains("cert_remaining_max_seconds"))
        c.cert_remaining = number(v["cert_remaining_max_seconds"], 86400);
    if (v.contains("cert_total_max_seconds")) c.cert_total = number(v["cert_total_max_seconds"], 86400);
    if (v.contains("minimum_interval_seconds")) c.interval = number(v["minimum_interval_seconds"], 86400);
    if (v.contains("certificate_cn")) c.certificate_cn = v["certificate_cn"];
    if (v.contains("require_full_tgt_lifetime"))
    {
        const auto &value = v["require_full_tgt_lifetime"];
        need(value == "yes" || value == "no", "require_full_tgt_lifetime must be yes or no");
        c.require_full_tgt_lifetime = value == "yes";
    }
    need(c.certificate_cn.size() <= 256, "certificate CN pattern is too long");
    need(c.tgt >= 60 && (c.renew == 0 || c.renew >= c.tgt) && c.cert_remaining >= 60 &&
             c.cert_total >= c.cert_remaining && c.interval >= 30,
         "invalid lifetime/rate limits");
    return c;
}

inline Config config()
{
    return parse_config(root_text(path("config")));
}

// Encode bounded ASN.1 structures without generating CA signatures.
inline Bytes join(Bytes a, ByteView b)
{
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

inline Bytes der(unsigned char tag, ByteView value)
{
    Bytes b{tag};
    size_t n = value.size();
    if (n < 128) b.push_back(static_cast<unsigned char>(n));
    else
    {
        Bytes len;
        while (n)
        {
            len.insert(len.begin(), static_cast<unsigned char>(n & 255));
            n >>= 8;
        }
        b.push_back(static_cast<unsigned char>(0x80 | len.size()));
        b = join(std::move(b), len);
    }
    return join(std::move(b), value);
}

inline Bytes bmp(const std::string &s)
{
    Bytes b;
    for (unsigned char ch : s)
    {
        need(ch >= 32 && ch < 127, "non-ASCII enrollment attribute");
        b.push_back(0);
        b.push_back(ch);
    }
    return der(0x1e, b);
}

inline Bytes oid_der(const std::string &s)
{
    Obj o(OBJ_txt2obj(s.c_str(), 1));
    sslneed(o != nullptr, "OID parse");
    int n = i2d_ASN1_OBJECT(o.get(), nullptr);
    sslneed(n > 0, "OID length");
    Bytes b(static_cast<size_t>(n));
    auto p = b.data();
    i2d_ASN1_OBJECT(o.get(), &p);
    return b;
}

inline std::string base64(ByteView b)
{
    need(b.size() <= MAX_BLOB, "base64 input too large");
    std::string s(4 * ((b.size() + 2) / 3) + 1, '\0');
    int n =
        EVP_EncodeBlock(reinterpret_cast<unsigned char *>(s.data()), b.data(), static_cast<int>(b.size()));
    sslneed(n >= 0, "base64 encode");
    s.resize(static_cast<size_t>(n));
    return s;
}

inline Bytes unbase64(const std::string &input)
{
    // Sanitize base64 text and reject invalid whitespace
    need(input.size() <= 2 * MAX_BLOB, "invalid base64 length");
    std::string s = input;
    std::erase_if(s, [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; });
    need(!s.empty() && s.size() % 4 == 0, "invalid base64 length");
    const size_t padding = (s.back() == '=') + (s[s.size() - 2] == '=');
    const std::string_view payload(s.data(), s.size() - padding);
    need(payload.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") ==
             std::string_view::npos,
         "invalid base64 character");

    // Decode base64 payload into raw binary bytes
    Bytes b(s.size() / 4 * 3);
    int n = EVP_DecodeBlock(
        b.data(), reinterpret_cast<const unsigned char *>(s.data()), static_cast<int>(s.size()));
    sslneed(n >= 0 && static_cast<size_t>(n) >= padding, "base64 decode");
    b.resize(static_cast<size_t>(n) - padding);
    return b;
}

inline Bio membio(ByteView b)
{
    need(b.size() <= 8 * MAX_BLOB, "BIO too large");
    Bio bio(BIO_new_mem_buf(b.data(), static_cast<int>(b.size())));
    sslneed(bio != nullptr, "BIO allocate");
    return bio;
}

inline Bytes biobytes(BIO *b)
{
    char *p = nullptr;
    long n = BIO_get_mem_data(b, &p);
    need(n >= 0 && static_cast<size_t>(n) <= MAX_BLOB, "BIO size");
    return Bytes(p, p + n);
}

inline Cert load_cert(const char *file)
{
    Fd f = root_open(path(file));
    Bytes b = read_all(f.get());
    Bio bio = membio(b);
    Cert x(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    sslneed(x != nullptr, "read certificate");
    return x;
}

inline int no_pem_password(char *, int, int, void *)
{
    return 0;
}

// Erase serialized private-key bytes on both success and exception paths.
inline Key load_key(const char *file)
{
    Fd f = root_open(path(file), true);
    Bytes b = read_all(f.get());
    ScopeExit erase([&]() noexcept { wipe(b); });
    Bio bio = membio(b);
    Key k(PEM_read_bio_PrivateKey(bio.get(), nullptr, no_pem_password, nullptr));
    sslneed(k != nullptr,
            "read noninteractive PEM private key (encrypted PEM needs a different key backend)");
    return k;
}

inline Key generate_key()
{
    Owned<EVP_PKEY_CTX, EVP_PKEY_CTX_free> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    sslneed(ctx && EVP_PKEY_keygen_init(ctx.get()) > 0 &&
                EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 3072) > 0,
            "RSA key generation init");
    Key key;
    sslneed(EVP_PKEY_keygen(ctx.get(), out(key)) > 0, "RSA key generation");
    return key;
}

inline Ext raw_extension(const char *oid, ByteView bytes)
{
    Obj o(OBJ_txt2obj(oid, 1));
    Owned<ASN1_OCTET_STRING, ASN1_OCTET_STRING_free> data(ASN1_OCTET_STRING_new());
    sslneed(o && data && ASN1_OCTET_STRING_set(data.get(), bytes.data(), static_cast<int>(bytes.size())) == 1,
            "extension value");
    Ext e(X509_EXTENSION_create_by_OBJ(nullptr, o.get(), 0, data.get()));
    sslneed(e != nullptr, "extension create");
    return e;
}

// Expand only administrator-configured CN placeholders; identity still comes from the directory UPN.
inline std::string common_name(const Config &cfg, std::string_view user, std::string_view upn)
{
    // Substitute placeholders in configured common name pattern
    std::string cn;
    const std::string_view pattern = cfg.certificate_cn;
    for (size_t pos = 0; pos < pattern.size();)
    {
        if (pattern[pos] != '{')
        {
            cn += pattern[pos++];
            continue;
        }
        const auto end = pattern.find('}', pos);
        const auto token = pattern.substr(pos, end == pattern.npos ? pattern.npos : end - pos + 1);
        if (token == "{user}") cn += user;
        else if (token == "{upn}") cn += upn;
        else if (token == "{domain}") cn += cfg.domain;
        else fail("unknown certificate CN placeholder");
        pos = end + 1;
    }

    // Validate generated CN string constraints
    need(!cn.empty() && cn.size() <= 64 && cn.find_first_of("{}") == cn.npos &&
             std::ranges::all_of(cn, [](unsigned char c) { return c >= 32 && c < 127; }),
         "certificate CN must expand to 1..64 printable ASCII characters; unknown placeholder");
    return cn;
}

// Request a non-CA PKINIT leaf; the CA template remains authoritative for the issued subject.
inline Req
make_request(EVP_PKEY *key, const std::string &upn, const std::string &template_id, const std::string &cn)
{
    Req req(X509_REQ_new());
    sslneed(req && X509_REQ_set_version(req.get(), 0) == 1 && X509_REQ_set_pubkey(req.get(), key) == 1,
            "CSR initialize");
    Owned<X509_NAME, X509_NAME_free> name(X509_NAME_new());
    sslneed(name &&
                X509_NAME_add_entry_by_txt(name.get(),
                                           "CN",
                                           MBSTRING_ASC,
                                           reinterpret_cast<const unsigned char *>(cn.data()),
                                           static_cast<int>(cn.size()),
                                           -1,
                                           0) == 1 &&
                X509_REQ_set_subject_name(req.get(), name.get()) == 1,
            "CSR common name");
    Extensions exts(sk_X509_EXTENSION_new_null());
    sslneed(exts != nullptr, "CSR extension stack");
    auto add = [&](Ext e)
    {
        sslneed(e && sk_X509_EXTENSION_push(exts.get(), e.get()) > 0, "CSR extension append");
        (void)e.release();
    };

    // Encode the Microsoft UPN otherName and request the pinned template, never a chosen SID.
    Bytes text(upn.begin(), upn.end());
    add(raw_extension("2.5.29.17", der(0x30, der(0xa0, join(oid_der(UPN_OID), der(0xa0, der(0x0c, text)))))));
    add(raw_extension(TEMPLATE_OID, der(0x30, join(oid_der(template_id), der(0x02, Bytes{1})))));
    add(Ext(X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_basic_constraints, const_cast<char *>("critical,CA:FALSE"))));
    add(Ext(X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_key_usage, const_cast<char *>("critical,digitalSignature,keyEncipherment"))));
    add(Ext(X509V3_EXT_conf_nid(nullptr,
                                nullptr,
                                NID_ext_key_usage,
                                const_cast<char *>("clientAuth,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.2.3.4"))));
    sslneed(X509_REQ_add_extensions(req.get(), exts.get()) == 1, "CSR add extensions");
    sslneed(X509_REQ_sign(req.get(), key, EVP_sha256()) > 0, "CSR self-signature");
    return req;
}

inline Bytes request_der(X509_REQ *req)
{
    int n = i2d_X509_REQ(req, nullptr);
    sslneed(n > 0, "CSR DER length");
    Bytes b(static_cast<size_t>(n));
    auto p = b.data();
    sslneed(i2d_X509_REQ(req, &p) == n, "CSR DER");
    return b;
}

// Sign enrollment on behalf of the fixed requester using the enrollment-agent key.
inline Bytes wrap_eobo(X509_REQ *req, X509 *agent, EVP_PKEY *agent_key, const std::string &requester)
{
    Bytes csr = request_der(req);
    Bio data = membio(csr);
    Cms cms(CMS_sign(nullptr, nullptr, nullptr, nullptr, CMS_BINARY | CMS_PARTIAL));
    sslneed(cms != nullptr, "CMS initialize");
    CMS_SignerInfo *signer = CMS_add1_signer(cms.get(), agent, agent_key, EVP_sha256(), CMS_NOSMIMECAP);
    sslneed(signer != nullptr, "CMS enrollment-agent signer");

    // The Attribute SET contains one SEQUENCE { BMPString name, BMPString value }.
    Bytes pair = der(0x30, join(bmp("requestername"), bmp(requester)));
    Obj oid(OBJ_txt2obj(ENROLL_PAIR_OID, 1));
    sslneed(CMS_signed_add1_attr_by_OBJ(
                signer, oid.get(), V_ASN1_SEQUENCE, pair.data(), static_cast<int>(pair.size())) == 1,
            "CMS signed requestername");
    sslneed(CMS_final(cms.get(), data.get(), nullptr, CMS_BINARY) == 1, "CMS sign");
    int n = i2d_CMS_ContentInfo(cms.get(), nullptr);
    sslneed(n > 0, "CMS size");
    Bytes b(static_cast<size_t>(n));
    auto p = b.data();
    sslneed(i2d_CMS_ContentInfo(cms.get(), &p) == n, "CMS DER");
    return b;
}

// Read certificate extensions while rejecting absent or ambiguous identity bindings.
inline bool has_eku(X509 *cert, const std::string &oid)
{
    int critical{};
    Owned<EXTENDED_KEY_USAGE, EXTENDED_KEY_USAGE_free> usages(
        static_cast<EXTENDED_KEY_USAGE *>(X509_get_ext_d2i(cert, NID_ext_key_usage, &critical, nullptr)));
    return usages &&
           std::ranges::any_of(std::views::iota(0, sk_ASN1_OBJECT_num(usages.get())),
                               [&](int i) { return objtext(sk_ASN1_OBJECT_value(usages.get(), i)) == oid; });
}

inline Bytes extension_bytes(X509 *x, const char *oid)
{
    Obj o(OBJ_txt2obj(oid, 1));
    sslneed(o != nullptr, "extension OID");
    int i = X509_get_ext_by_OBJ(x, o.get(), -1);
    need(i >= 0 && X509_get_ext_by_OBJ(x, o.get(), i) < 0,
         std::string("missing/duplicate certificate extension ") + oid);
    ASN1_OCTET_STRING *d = X509_EXTENSION_get_data(X509_get_ext(x, i));
    return Bytes(ASN1_STRING_get0_data(d), ASN1_STRING_get0_data(d) + ASN1_STRING_length(d));
}

inline std::string certificate_upn(X509 *c)
{
    Bytes b = extension_bytes(c, "2.5.29.17");
    const unsigned char *p = b.data();
    Owned<GENERAL_NAMES, GENERAL_NAMES_free> names(
        d2i_GENERAL_NAMES(nullptr, &p, static_cast<long>(b.size())));
    sslneed(names && p == b.data() + b.size(), "decode SAN");
    std::string upn;
    int count = 0;
    for (int i = 0; i < sk_GENERAL_NAME_num(names.get()); ++i)
    {
        GENERAL_NAME *n = sk_GENERAL_NAME_value(names.get(), i);
        if (n->type == GEN_OTHERNAME && objtext(n->d.otherName->type_id) == UPN_OID)
        {
            ASN1_TYPE *v = n->d.otherName->value;
            need(v->type == V_ASN1_UTF8STRING, "UPN must be UTF8String");
            upn.assign(reinterpret_cast<const char *>(ASN1_STRING_get0_data(v->value.utf8string)),
                       static_cast<size_t>(ASN1_STRING_length(v->value.utf8string)));
            ++count;
        }
    }
    need(count == 1, "certificate must contain exactly one UPN otherName");
    return upn;
}

inline std::string certificate_template(X509 *cert)
{
    const auto bytes = extension_bytes(cert, TEMPLATE_OID);
    const auto *cursor = bytes.data();
    Asn1Sequence sequence(d2i_ASN1_SEQUENCE_ANY(nullptr, &cursor, static_cast<long>(bytes.size())));
    sslneed(sequence != nullptr, "decode template extension");
    const int count = sk_ASN1_TYPE_num(sequence.get());
    need(cursor == bytes.data() + bytes.size() && count >= 1 && count <= 3, "invalid template extension");
    const auto *id = sk_ASN1_TYPE_value(sequence.get(), 0);
    need(id->type == V_ASN1_OBJECT, "template identifier must be OID");
    for (int i = 1; i < count; ++i)
    {
        const auto *version = sk_ASN1_TYPE_value(sequence.get(), i);
        uint64_t value{};
        need(version->type == V_ASN1_INTEGER &&
                 ASN1_INTEGER_get_uint64(&value, version->value.integer) == 1 && value <= UINT32_MAX,
             "template version must be an unsigned 32-bit integer");
    }
    return objtext(id->value.object);
}

inline time_t as_time(const ASN1_TIME *a)
{
    struct tm t{};
    sslneed(ASN1_TIME_to_tm(a, &t) == 1, "certificate time");
    time_t result = timegm(&t);
    need(result != -1, "invalid certificate timestamp");
    return result;
}

// Verify CA trust and revocation before accepting any logon certificate.
inline void verify_chain(X509 *x)
{
    // Require administrator-supplied trust and current CRLs without online fetching.
    root_open(path("ca-trust.pem"));
    root_open(path("ca-crls.pem"));
    Owned<X509_STORE, X509_STORE_free> s(X509_STORE_new());
    sslneed(s != nullptr, "X509 store");
    sslneed(X509_STORE_load_locations(s.get(), path("ca-trust.pem").c_str(), nullptr) == 1, "load CA trust");
    X509_LOOKUP *lookup = X509_STORE_add_lookup(s.get(), X509_LOOKUP_file());
    sslneed(lookup != nullptr, "CRL lookup");
    sslneed(X509_load_crl_file(lookup, path("ca-crls.pem").c_str(), X509_FILETYPE_PEM) > 0, "load CRLs");
    sslneed(X509_STORE_set_flags(s.get(), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) == 1,
            "enable CRL checks");
    Owned<X509_STORE_CTX, X509_STORE_CTX_free> ctx(X509_STORE_CTX_new());
    sslneed(ctx && X509_STORE_CTX_init(ctx.get(), s.get(), x, nullptr) == 1, "X509 verify init");
    if (X509_verify_cert(ctx.get()) != 1)
        fail(std::string("certificate trust/revocation failed: ") +
             X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get())));
}

// Enforce the pinned key, UPN, template, usage, and short validity.
inline time_t validate_leaf(X509 *c, EVP_PKEY *key, const Mapping &m, const Config &cfg)
{
    sslneed(X509_check_private_key(c, key) == 1, "issued certificate public key mismatch");
    int bc_critical{};
    Owned<BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free> bc(
        static_cast<BASIC_CONSTRAINTS *>(X509_get_ext_d2i(c, NID_basic_constraints, &bc_critical, nullptr)));
    need(bc && !bc->ca && !bc->pathlen && X509_check_ca(c) == 0, "user certificate needs CA:FALSE");
    need(has_eku(c, SMARTCARD_OID) && has_eku(c, CLIENT_AUTH_OID) && has_eku(c, PKINIT_CLIENT_OID),
         "issued certificate needs Smart Card Logon, Client Authentication and PKINIT Client Authentication "
         "EKUs");
    int critical = 0;
    Owned<ASN1_BIT_STRING, ASN1_BIT_STRING_free> ku(
        static_cast<ASN1_BIT_STRING *>(X509_get_ext_d2i(c, NID_key_usage, &critical, nullptr)));
    need(ku && ASN1_BIT_STRING_get_bit(ku.get(), 0) == 1 && !ASN1_BIT_STRING_get_bit(ku.get(), 5) &&
             !ASN1_BIT_STRING_get_bit(ku.get(), 6),
         "certificate needs digitalSignature and must not authorize certificate/CRL signing");
    const std::string expected_upn = m.upn.empty() ? (m.name + "@" + cfg.domain) : m.upn;
    need(certificate_upn(c) == expected_upn, "issued UPN differs from Active Directory UPN");
    need(certificate_template(c) == cfg.template_oid, "CA returned the wrong certificate template");
    time_t now = time(nullptr), start = as_time(X509_get0_notBefore(c)), end = as_time(X509_get0_notAfter(c));
    need(start <= now && end > now + 60, "certificate is not currently valid for at least 60 seconds");
    need(end - start > 0 && end - start <= cfg.cert_total,
         "CA issued a certificate with excessive total validity");
    need(end - now <= cfg.cert_remaining,
         "CA issued a certificate with excessive remaining validity; configure the short-lived template");
    return end;
}

inline std::string xml_escape(const std::string &s)
{
    std::string out;
    for (char c : s)
    {
        switch (c)
        {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&apos;";
            break;
        default:
            need(static_cast<unsigned char>(c) >= 32, "control in XML text");
            out += c;
        }
    }
    return out;
}
inline constexpr char SOAP_NS[] = "http://www.w3.org/2003/05/soap-envelope";
inline constexpr char TRUST_NS[] = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
inline constexpr char SECURITY_NS[] =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
inline constexpr char X509_TOKEN[] =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
inline constexpr char ENROLL_NS[] = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";

// Construct the WSTEP request carrying the complete signed CMS token.
inline std::string soap_request(const Config &c, ByteView cms)
{
    std::string id = random_hex();
    id[12] = '4';
    id[16] = "89ab"[(id[16] >= 'a' ? id[16] - 'a' + 10 : id[16] - '0') & 3];
    id.insert(20, "-");
    id.insert(16, "-");
    id.insert(12, "-");
    id.insert(8, "-");

    // The complete CMS, including the signed requestername, is the PKCS7 token.
    return std::string("<?xml version=\"1.0\" encoding=\"utf-8\"?>") + "<s:Envelope xmlns:s=\"" + SOAP_NS +
           "\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:t=\"" + TRUST_NS + "\" xmlns:o=\"" +
           SECURITY_NS + "\" xmlns:e=\"" + ENROLL_NS +
           "\">"
           "<s:Header><a:Action s:mustUnderstand=\"1\">" +
           ENROLL_NS + "/RST/wstep</a:Action><a:MessageID>urn:uuid:" + id +
           "</a:MessageID>"
           "<a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>"
           "<a:To s:mustUnderstand=\"1\">" +
           xml_escape(c.ces_url) +
           "</a:To></s:Header><s:Body><t:RequestSecurityToken>"
           "<t:TokenType>" +
           X509_TOKEN + "</t:TokenType><t:RequestType>" + TRUST_NS +
           "/Issue</t:RequestType>"
           "<o:BinarySecurityToken ValueType=\"" +
           SECURITY_NS + "#PKCS7\" EncodingType=\"" + SECURITY_NS + "#base64binary\">" + base64(cms) +
           "</o:BinarySecurityToken>"
           "<e:RequestID xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/>"
           "</t:RequestSecurityToken></s:Body></s:Envelope>";
}

inline xmlNodePtr one(xmlDocPtr doc, const char *expr, bool required = true)
{
    Owned<xmlXPathContext, xmlXPathFreeContext> ctx(xmlXPathNewContext(doc));
    need(ctx != nullptr, "XML XPath context");
    need(xmlXPathRegisterNs(ctx.get(), BAD_CAST "s", BAD_CAST SOAP_NS) == 0 &&
             xmlXPathRegisterNs(ctx.get(), BAD_CAST "t", BAD_CAST TRUST_NS) == 0 &&
             xmlXPathRegisterNs(ctx.get(), BAD_CAST "o", BAD_CAST SECURITY_NS) == 0,
         "XML namespaces");
    Owned<xmlXPathObject, xmlXPathFreeObject> res(xmlXPathEvalExpression(BAD_CAST expr, ctx.get()));
    need(res != nullptr, "XPath evaluation");
    int n = res->nodesetval ? res->nodesetval->nodeNr : 0;
    need(n <= 1 && (!required || n == 1), "missing or ambiguous SOAP element");
    return n ? res->nodesetval->nodeTab[0] : nullptr;
}

inline std::string node_text(xmlNodePtr node)
{
    XmlText text(xmlNodeGetContent(node));
    need(text != nullptr, "empty XML text");
    return reinterpret_cast<const char *>(text.get());
}

inline std::string safe_message(std::string s)
{
    // Bound error message size and sanitize non-printable control characters
    if (s.size() > 500)
    {
        s.resize(500);
    }
    const static std::regex control_re(R"([\x00-\x1f\x7f])");
    return std::regex_replace(s, control_re, " ");
}

inline Owned<xmlDoc, xmlFreeDoc> parse_soap(const std::string &body)
{
    need(body.size() <= 2 * MAX_BLOB, "SOAP response exceeds limit");

    // Reject DTDs/entities and keep expansion, XInclude, and huge-document modes disabled.
    need(body.find("<!DOCTYPE") == std::string::npos && body.find("<!ENTITY") == std::string::npos,
         "DTD/entity declarations are forbidden");
    Owned<xmlDoc, xmlFreeDoc> doc(xmlReadMemory(body.data(),
                                                static_cast<int>(body.size()),
                                                "response.xml",
                                                nullptr,
                                                XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING));
    need(doc && !doc->intSubset && !doc->extSubset, "invalid SOAP XML or forbidden DTD");
    return doc;
}

// Parse a bounded response and require a unique certificate for the generated key.
inline Cert parse_response(const std::string &body, EVP_PKEY *expected_key)
{
    auto doc = parse_soap(body);
    if (auto f = one(doc.get(), "/s:Envelope/s:Body/s:Fault", false))
        fail("CES SOAP fault: " + safe_message(node_text(f)));
    const char *expr =
        "/s:Envelope/s:Body/t:RequestSecurityTokenResponseCollection/t:RequestSecurityTokenResponse/"
        "t:RequestedSecurityToken/o:BinarySecurityToken | "
        "/s:Envelope/s:Body/t:RequestSecurityTokenResponse/t:RequestedSecurityToken/o:BinarySecurityToken";
    auto token = one(doc.get(), expr, false);
    need(token != nullptr,
         "CES returned no issued certificate (possibly pending/denied); inspect CA/CES logs; pending polling "
         "is not implemented");
    auto property = [&](const char *name)
    {
        XmlText value(xmlGetProp(token, BAD_CAST name));
        return value ? std::string(reinterpret_cast<const char *>(value.get())) : std::string{};
    };
    const auto encoding = property("EncodingType"), type = property("ValueType");
    need(encoding == std::string(SECURITY_NS) + "#base64binary", "unsupported certificate token encoding");
    Bytes data = unbase64(node_text(token));
    const unsigned char *p = data.data();
    if (type == X509_TOKEN)
    {
        Cert c(d2i_X509(nullptr, &p, static_cast<long>(data.size())));
        sslneed(c && p == data.data() + data.size(), "parse issued X509 certificate");
        return c;
    }
    need(type == std::string(SECURITY_NS) + "#PKCS7", "unsupported certificate token type");
    Cms cms(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(data.size())));
    sslneed(cms && p == data.data() + data.size(), "parse issued CMS chain");
    Certificates certs(CMS_get1_certs(cms.get()));
    sslneed(certs != nullptr, "issued CMS has no certificates");
    Cert result;
    int count = 0;
    for (int i = 0; i < sk_X509_num(certs.get()); ++i)
    {
        X509 *c = sk_X509_value(certs.get(), i);
        Key pub(X509_get_pubkey(c));
        if (pub && EVP_PKEY_eq(pub.get(), expected_key) == 1)
        {
            sslneed(X509_up_ref(c) == 1, "certificate reference");
            result.reset(c);
            ++count;
        }
    }
    need(count == 1, "response must contain exactly one certificate for the new key");
    return result;
}

// Keep the context alive longer than every context-dependent RAII resource.
class Kerberos
{
    KrbContext context_;
    KrbCache transport_;

public:
    Kerberos() : transport_(nullptr, {nullptr})
    {
        root_open(path("krb5.conf"));
        const auto code = krb5_init_context(out(context_));
        check(code, "initialize MIT Kerberos");
        transport_ = KrbCache(nullptr, {ctx()});
    }

    [[nodiscard]] krb5_context ctx() const noexcept
    {
        return context_.get();
    }

    void check(krb5_error_code code, const std::string &operation) const
    {
        if (!code) return;
        auto message =
            krb_owner<const char, krb5_free_error_message>(ctx(), krb5_get_error_message(ctx(), code));
        fail(operation + ": " + (message ? message.get() : "unknown Kerberos error"));
    }

    void acquire_transport(const Config &c)
    {
        root_open(path("submitter.keytab"), true);
        auto p = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(ctx());
        auto kt = krb_owner<std::remove_pointer_t<krb5_keytab>, krb5_kt_close>(ctx());
        auto o = krb_owner<krb5_get_init_creds_opt, krb5_get_init_creds_opt_free>(ctx());
        krb5_creds cred{};
        ScopeExit free_cred([&]() noexcept { krb5_free_cred_contents(ctx(), &cred); });
        check(krb5_parse_name(ctx(), c.service_principal.c_str(), out(p)), "parse transport principal");
        check(krb5_kt_resolve(ctx(), ("FILE:" + path("submitter.keytab")).c_str(), out(kt)),
              "open transport keytab");
        check(krb5_get_init_creds_opt_alloc(ctx(), out(o)), "transport options");
        auto types = AES_TYPES;
        krb5_get_init_creds_opt_set_etype_list(o.get(), types.data(), static_cast<int>(types.size()));
        krb5_get_init_creds_opt_set_tkt_life(o.get(), 300);
        krb5_get_init_creds_opt_set_renew_life(o.get(), 0);

        // Only the isolated transport account requests forwardability for CES constrained delegation.
        krb5_get_init_creds_opt_set_forwardable(o.get(), c.ces_auth == "negotiate");
        krb5_get_init_creds_opt_set_proxiable(o.get(), 0);
        check(krb5_get_init_creds_keytab(ctx(), &cred, p.get(), kt.get(), 0, nullptr, o.get()),
              "authenticate directory/CES transport account");
        require_aes_key(cred.keyblock);
        (void)ticket_enctype(ctx(), cred.ticket);
        check(krb5_cc_new_unique(ctx(), "MEMORY", nullptr, out(transport_)), "transport memory cache");
        check(krb5_cc_initialize(ctx(), transport_.get(), p.get()), "initialize transport cache");
        check(krb5_cc_store_cred(ctx(), transport_.get(), &cred), "store transport credentials");
        auto full = krb_owner<char, krb5_free_string>(ctx());
        check(krb5_cc_get_full_name(ctx(), transport_.get(), out(full)), "transport cache name");
        sysneed(setenv("KRB5CCNAME", full.get(), 1) == 0, "set private transport cache");
    }
};

inline size_t receive(void *p, size_t size, size_t nmemb, void *target) noexcept
{
    auto &b = *static_cast<std::string *>(target);
    if (size && nmemb > SIZE_MAX / size) return 0;
    size_t n = size * nmemb;
    if (n > 2 * MAX_BLOB - b.size()) return 0;
    try
    {
        b.append(static_cast<char *>(p), n);
    }
    catch (...)
    {
        return 0;
    }
    return n;
}

// Submit enrollment over verified HTTPS using the configured transport identity.
inline std::string send_ces(const Config &cfg, const std::string &request)
{
    root_open(path("https-trust.pem"));
    Owned<CURL, curl_easy_cleanup> c(curl_easy_init());
    need(c != nullptr, "curl handle");
    Owned<CURLU, curl_url_cleanup> u(curl_url());
    need(u != nullptr, "URL handle");
    need(curl_url_set(u.get(), CURLUPART_URL, cfg.ces_url.c_str(), 0) == CURLUE_OK, "invalid CES URL");
    Owned<char, curl_free> scheme;
    need(curl_url_get(u.get(), CURLUPART_SCHEME, out(scheme), 0) == CURLUE_OK, "CES URL scheme");
    bool https = std::strcmp(scheme.get(), "https") == 0;
    need(https, "HTTPS is mandatory");
    for (CURLUPart part : {CURLUPART_USER, CURLUPART_PASSWORD, CURLUPART_QUERY, CURLUPART_FRAGMENT})
    {
        Owned<char, curl_free> value;
        CURLUcode rc = curl_url_get(u.get(), part, out(value), 0);
        bool present = rc == CURLUE_OK;
        need(!present, "credentials, query and fragment are not allowed in CES URL");
    }
    std::string response;
    char error[CURL_ERROR_SIZE]{};
    auto opt = [&](CURLoption o, auto value)
    {
        need(curl_easy_setopt(c.get(), o, value) == CURLE_OK, "curl option rejected");
    };
    opt(CURLOPT_URL, cfg.ces_url.c_str());
    opt(CURLOPT_POST, 1L);
    opt(CURLOPT_POSTFIELDS, request.c_str());
    opt(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.size()));
    opt(CURLOPT_SSL_VERIFYPEER, 1L);
    opt(CURLOPT_SSL_VERIFYHOST, 2L);
    opt(CURLOPT_CAINFO, path("https-trust.pem").c_str());
    opt(CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
    opt(CURLOPT_FOLLOWLOCATION, 0L);
    opt(CURLOPT_PROXY, "");
    opt(CURLOPT_NETRC, static_cast<long>(CURL_NETRC_IGNORED));
    opt(CURLOPT_CONNECTTIMEOUT, 10L);
    opt(CURLOPT_TIMEOUT, 40L);
    opt(CURLOPT_NOSIGNAL, 1L);
    opt(CURLOPT_HTTP_VERSION, static_cast<long>(CURL_HTTP_VERSION_1_1));
    opt(CURLOPT_WRITEFUNCTION, receive);
    opt(CURLOPT_WRITEDATA, &response);
    opt(CURLOPT_ERRORBUFFER, error);

    // Permit only configured Negotiate or mTLS; CES must disallow GSS NTLM fallback.
    if (cfg.ces_auth == "negotiate")
    {
        need(curl_version_info(CURLVERSION_NOW)->features & CURL_VERSION_SPNEGO,
             "libcurl lacks SPNEGO; use a distribution libcurl with GSSAPI/MIT Kerberos support");
        opt(CURLOPT_HTTPAUTH, static_cast<long>(CURLAUTH_NEGOTIATE));
        opt(CURLOPT_USERPWD, ":");
        opt(CURLOPT_GSSAPI_DELEGATION, static_cast<long>(CURLGSSAPI_DELEGATION_NONE));
    }
    else
    {
        root_open(path("https-client.pem"));
        root_open(path("https-client.key"), true);
        opt(CURLOPT_SSLCERT, path("https-client.pem").c_str());
        opt(CURLOPT_SSLKEY, path("https-client.key").c_str());
    }
    Owned<curl_slist, curl_slist_free_all> headers;
    for (auto text : {"Content-Type: application/soap+xml; charset=utf-8", "Expect:"})
    {
        auto *appended = curl_slist_append(headers.get(), text);
        need(appended != nullptr, "HTTP headers");
        (void)headers.release();
        headers.reset(appended);
    }
    opt(CURLOPT_HTTPHEADER, headers.get());
    CURLcode rc = curl_easy_perform(c.get());
    need(rc == CURLE_OK, std::string("CES HTTPS failure: ") + safe_message(error));
    long status = 0;
    need(curl_easy_getinfo(c.get(), CURLINFO_RESPONSE_CODE, &status) == CURLE_OK, "HTTP response status");

    // SOAP faults commonly have HTTP 500; parse them without treating them as success.
    need(status == 200 || status == 500,
         "CES HTTP status " + std::to_string(status) +
             " (check endpoint, TLS mapping, SPN and authentication)");
    if (status == 500)
    {
        // Decode a bounded SOAP fault only; never accept credentials in HTTP 500.
        auto doc = parse_soap(response);
        if (auto fault = one(doc.get(), "/s:Envelope/s:Body/s:Fault", false))
            fail("CES SOAP fault: " + safe_message(node_text(fault)));
        fail("CES HTTP 500; inspect CA/CES logs");
    }
    return response;
}

// Pass temporary PKINIT material through sealed, private memory files.
inline Fd memory_file(const char *name, ByteView b)
{
    Fd f(memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING));
    sysneed(f.get() >= 0, "memfd_create");
    sysneed(fchmod(f.get(), 0600) == 0, "memfd mode");
    write_all(f.get(), b);
    sysneed(lseek(f.get(), 0, SEEK_SET) == 0, "memfd rewind");
    sysneed(fcntl(f.get(), F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) == 0,
            "seal memfd");
    return f;
}

inline krb5_error_code refuse_prompt(krb5_context, void *, const char *, const char *, int, krb5_prompt[])
{
    return KRB5_LIBOS_CANTREADPWD;
}

// Validate the issued ticket, never rewrite its expiry or confuse renewal with validity.
inline void validate_tgt(krb5_context ctx,
                         const Config &cfg,
                         const krb5_creds &creds,
                         krb5_principal principal,
                         krb5_principal tgs,
                         time_t requested_at,
                         time_t now)
{
    need(krb5_principal_compare(ctx, creds.client, principal) &&
             krb5_principal_compare(ctx, creds.server, tgs),
         "KDC returned unexpected principal or non-TGT credentials");
    constexpr auto prohibited = TKT_FLG_FORWARDABLE | TKT_FLG_FORWARDED | TKT_FLG_PROXIABLE |
                                TKT_FLG_PROXY | TKT_FLG_MAY_POSTDATE |
                                TKT_FLG_POSTDATED | TKT_FLG_INVALID;
    need((creds.ticket_flags & TKT_FLG_PRE_AUTH) && (creds.ticket_flags & TKT_FLG_INITIAL) &&
             !(creds.ticket_flags & prohibited),
         "KDC returned prohibited flags or no initial/preauthentication flag");
    if (cfg.renew > 0)
    {
        need((creds.ticket_flags & TKT_FLG_RENEWABLE) != 0,
             "KDC did not return a renewable credential as configured");
        need(creds.times.renew_till > creds.times.endtime,
             "KDC returned a renewable credential with renew_till not exceeding endtime");
        const int64_t renew_start = creds.times.starttime ? creds.times.starttime : creds.times.authtime;
        const int64_t renew_duration = static_cast<int64_t>(creds.times.renew_till) - renew_start;
        need(renew_duration <= static_cast<int64_t>(cfg.renew) + 5 &&
                 static_cast<int64_t>(creds.times.renew_till) <= static_cast<int64_t>(now) + cfg.renew + 5,
             "KDC returned an excessive renewable lifetime; synchronize clocks");
        if (renew_duration + 5 < cfg.renew)
        {
            const auto message =
                std::format("KDC granted {} seconds renewable lifetime; requested {}. Review DC ticket renewal policy.",
                            renew_duration,
                            cfg.renew);
            if (cfg.require_full_tgt_lifetime) fail(message);
            std::cerr << "craft-worker: WARNING: " << message << '\n';
        }
    }
    else
    {
        need(!(creds.ticket_flags & TKT_FLG_RENEWABLE),
             "KDC returned a renewable flag when renewal was not requested");
        need(creds.times.renew_till == 0,
             "KDC returned a renewable credential when renewal was not requested");
    }
    require_aes_key(creds.keyblock);
    const int64_t start = creds.times.starttime ? creds.times.starttime : creds.times.authtime;
    const int64_t duration = static_cast<int64_t>(creds.times.endtime) - start;
    need(start >= static_cast<int64_t>(requested_at) - 300 && start <= static_cast<int64_t>(now) + 300 &&
             creds.times.endtime > now && duration > 0 && duration <= static_cast<int64_t>(cfg.tgt) + 5 &&
             static_cast<int64_t>(creds.times.endtime) <= static_cast<int64_t>(now) + cfg.tgt + 5,
         "KDC returned an excessive/invalid TGT lifetime; synchronize clocks");
    if (duration + 5 < cfg.tgt)
    {
        const auto message =
            std::format("KDC granted {} seconds; requested {}. Review DC ticket policy and "
                        "PKINIT certificate/key-lifetime limits; a renewal window is not ticket validity.",
                        duration,
                        cfg.tgt);
        if (cfg.require_full_tgt_lifetime) fail(message);
        std::cerr << "craft-worker: WARNING: " << message << '\n';
    }
}

// Request the configured TGT independently; the DC alone decides what lifetime it can issue.
inline Bytes
get_tgt(Kerberos &k, const Config &cfg, const Mapping &m, X509 *cert, EVP_PKEY *key, time_t cert_end)
{
    Bio certbio(BIO_new(BIO_s_mem())), keybio(BIO_new(BIO_s_mem()));
    sslneed(certbio && keybio, "PKINIT BIO allocate");
    const auto clear_key_bio = [&]() noexcept
    {
        char *data = nullptr;
        const auto length = BIO_get_mem_data(keybio.get(), &data);
        if (length > 0) OPENSSL_cleanse(data, static_cast<size_t>(length));
    };
    ScopeExit erase_bio(clear_key_bio);
    sslneed(PEM_write_bio_X509(certbio.get(), cert) == 1 &&
                PEM_write_bio_PrivateKey(keybio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) == 1,
            "serialize temporary PKINIT identity");
    Bytes cb = biobytes(certbio.get()), kb = biobytes(keybio.get());
    ScopeExit erase_key([&]() noexcept { wipe(kb); });
    Fd certfd = memory_file("craft-cert", cb), keyfd = memory_file("craft-key", kb);
    wipe(kb);
    clear_key_bio();
    const auto identity = std::format("FILE:/proc/self/fd/{},/proc/self/fd/{}", certfd.get(), keyfd.get());
    auto principal = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(k.ctx());
    auto tgs = krb_owner<std::remove_pointer_t<krb5_principal>, krb5_free_principal>(k.ctx());
    auto opts = krb_owner<krb5_get_init_creds_opt, krb5_get_init_creds_opt_free>(k.ctx());
    krb5_creds creds{};
    ScopeExit free_creds([&]() noexcept { krb5_free_cred_contents(k.ctx(), &creds); });
    std::string name = m.name + "@" + cfg.realm;
    k.check(krb5_parse_name(k.ctx(), name.c_str(), out(principal)), "parse user principal");
    k.check(krb5_parse_name(k.ctx(), ("krbtgt/" + cfg.realm + "@" + cfg.realm).c_str(), out(tgs)),
            "parse TGS principal");
    k.check(krb5_get_init_creds_opt_alloc(k.ctx(), out(opts)), "PKINIT options");
    time_t requested_at = time(nullptr);
    const auto lifetime = static_cast<krb5_deltat>(cfg.tgt);
    const auto renew_lifetime = static_cast<krb5_deltat>(cfg.renew);
    need(cert_end > requested_at + 30, "certificate is too close to expiration");
    auto types = AES_TYPES;
    krb5_get_init_creds_opt_set_etype_list(opts.get(), types.data(), static_cast<int>(types.size()));
    krb5_get_init_creds_opt_set_tkt_life(opts.get(), lifetime);
    krb5_get_init_creds_opt_set_renew_life(opts.get(), renew_lifetime);
    krb5_get_init_creds_opt_set_forwardable(opts.get(), 0);
    krb5_get_init_creds_opt_set_proxiable(opts.get(), 0);
    krb5_get_init_creds_opt_set_canonicalize(opts.get(), 0);
    krb5_get_init_creds_opt_set_change_password_prompt(opts.get(), 0);
    krb5_preauthtype pa = KRB5_PADATA_PK_AS_REQ;
    krb5_get_init_creds_opt_set_preauth_list(opts.get(), &pa, 1);
    k.check(krb5_get_init_creds_opt_set_pa(k.ctx(), opts.get(), "X509_user_identity", identity.c_str()),
            "set PKINIT certificate and key");
    k.check(krb5_get_init_creds_opt_set_pa(
                k.ctx(), opts.get(), "X509_anchors", ("FILE:" + path("kdc-trust.pem")).c_str()),
            "set KDC trust anchors");

    // NULL password plus refusing all prompts: no password/keytab fallback for users.
    k.check(
        krb5_get_init_creds_password(
            k.ctx(), &creds, principal.get(), nullptr, refuse_prompt, nullptr, 0, nullptr, opts.get()),
        "user PKINIT");
    validate_tgt(k.ctx(), cfg, creds, principal.get(), tgs.get(), requested_at, time(nullptr));
    const auto outer = ticket_enctype(k.ctx(), creds.ticket);
    if (creds.times.renew_till > 0)
    {
        std::cerr << std::format(
            "craft-worker: TGT expires at Unix {} (renewable until Unix {}); session enctype={}; ticket enctype={}\n",
            creds.times.endtime,
            creds.times.renew_till,
            creds.keyblock.enctype,
            outer);
    }
    else
    {
        std::cerr << std::format("craft-worker: TGT expires at Unix {}; session enctype={}; ticket enctype={}\n",
                                 creds.times.endtime,
                                 creds.keyblock.enctype,
                                 outer);
    }
    return file_cache(k.ctx(), creds);
}

// Serialize each user's enrollment attempts and enforce the minimum interval.
inline Fd rate_limit(uid_t uid, uint32_t interval)
{
    Fd dir(open("/run/craft", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    sysneed(dir.get() >= 0, "open private runtime directory");
    struct stat st{};
    sysneed(fstat(dir.get(), &st) == 0, "stat runtime directory");
    need(st.st_uid == getuid() && (st.st_mode & 0077) == 0,
         "runtime directory must be dedicated-account owned, mode 0700");
    std::string n = std::to_string(uid) + ".lock";
    Fd f(openat(dir.get(), n.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600));
    sysneed(f.get() >= 0, "open per-user issuance lock");
    sysneed(fstat(f.get(), &st) == 0, "stat issuance lock");
    need(S_ISREG(st.st_mode) && st.st_uid == getuid() && st.st_nlink == 1 && !(st.st_mode & 0077),
         "unsafe issuance lock");
    sysneed(flock(f.get(), LOCK_EX | LOCK_NB) == 0, "another issuance is already running for this user");
    Bytes old = read_all(f.get(), 32);
    time_t now = time(nullptr);
    if (!old.empty())
    {
        auto then = number(trim(std::string(old.begin(), old.end())));
        need(now >= then && static_cast<uint64_t>(now - then) >= interval,
             "per-user enrollment rate limit reached");
    }
    std::string t = std::to_string(now) + "\n";
    sysneed(lseek(f.get(), 0, SEEK_SET) == 0 && ftruncate(f.get(), 0) == 0, "update issuance lock");
    write_all(f.get(), byte_view(t));
    return f;
}

inline Fd rate_limit(const Mapping &m, uint32_t interval)
{
    return rate_limit(m.uid, interval);
}

inline void free_ldap(LDAP *ld) noexcept
{
    if (ld) (void)ldap_unbind_ext_s(ld, nullptr, nullptr);
}

inline void free_ldap_msg(LDAPMessage *m) noexcept
{
    if (m) (void)ldap_msgfree(m);
}
using ScopedLdap = Owned<LDAP, free_ldap>;
using ScopedLdapMsg = Owned<LDAPMessage, free_ldap_msg>;

inline int ldap_sasl_interact(LDAP *, unsigned, void *, void *in) noexcept
{
    auto *interact = static_cast<sasl_interact_t *>(in);
    while (interact && interact->id != SASL_CB_LIST_END)
    {
        interact->result = nullptr;
        interact->len = 0;
        ++interact;
    }
    return LDAP_SUCCESS;
}

inline Mapping lookup_ad_user(const Config &cfg, uid_t uid, const std::string &name)
{
    need(simple_name(name), "invalid username for directory query");
    ScopedLdap ld;
    int rc = ldap_initialize(out(ld), cfg.gc_url.c_str());
    need(rc == LDAP_SUCCESS && ld,
         std::format("LDAP initialize failed for {}: {}", cfg.gc_url, ldap_err2string(rc)));
    int version = LDAP_VERSION3;
    const ber_len_t min_ssf = 1;
    struct timeval tv{10, 0};
    need(ldap_set_option(ld.get(), LDAP_OPT_PROTOCOL_VERSION, &version) == LDAP_OPT_SUCCESS &&
             ldap_set_option(ld.get(), LDAP_OPT_REFERRALS, LDAP_OPT_OFF) == LDAP_OPT_SUCCESS &&
             ldap_set_option(ld.get(), LDAP_OPT_NETWORK_TIMEOUT, &tv) == LDAP_OPT_SUCCESS &&
             ldap_set_option(ld.get(), LDAP_OPT_TIMEOUT, &tv) == LDAP_OPT_SUCCESS &&
             ldap_set_option(ld.get(), LDAP_OPT_X_SASL_SSF_MIN, &min_ssf) == LDAP_OPT_SUCCESS,
         "LDAP protocol, timeout or integrity options rejected");

    rc = ldap_sasl_interactive_bind_s(
        ld.get(), nullptr, "GSSAPI", nullptr, nullptr, LDAP_SASL_QUIET, ldap_sasl_interact, nullptr);
    need(rc == LDAP_SUCCESS,
         std::format("LDAP GSSAPI bind failed to {}: {}", cfg.gc_url, ldap_err2string(rc)));

    std::string base_dn = cfg.gc_base_dn.empty() ? domain_to_dn(cfg.domain) : cfg.gc_base_dn;
    std::string filter = std::format("(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))", name);
    const char *attrs[] = {"userPrincipalName", nullptr};

    ScopedLdapMsg res;
    rc = ldap_search_ext_s(ld.get(),
                           base_dn.c_str(),
                           LDAP_SCOPE_SUBTREE,
                           filter.c_str(),
                           const_cast<char **>(attrs),
                           0,
                           nullptr,
                           nullptr,
                           &tv,
                           2,
                           out(res));
    need(rc == LDAP_SUCCESS && res, std::format("LDAP search failed: {}", ldap_err2string(rc)));

    int count = ldap_count_entries(ld.get(), res.get());
    need(count > 0, std::format("user '{}' not found in Active Directory", name));
    need(count == 1, std::format("ambiguous user '{}': multiple Active Directory entries found", name));

    LDAPMessage *entry = ldap_first_entry(ld.get(), res.get());
    need(entry != nullptr, "failed to get LDAP entry");

    Owned<berval *, ldap_value_free_len> upn_vals(ldap_get_values_len(ld.get(), entry, "userPrincipalName"));
    need(!upn_vals || ldap_count_values_len(upn_vals.get()) <= 1,
         "Active Directory entry has multiple userPrincipalName values");
    const auto *upn = upn_vals ? *upn_vals : nullptr;
    const auto upn_str = upn && upn->bv_len ? std::string(upn->bv_val, upn->bv_len) : name + "@" + cfg.domain;

    return Mapping{.uid = uid, .name = name, .upn = upn_str};
}
} // namespace craft

#ifndef CRAFT_TEST
int main(int argc, char **argv)
{
    using namespace craft;
    uid_t requesting_uid = 0;
    try
    {
        // Reset inherited state and enforce the dedicated worker credentials.
        need(argc == 3, "worker is not a public interface; use craft");
        sysneed(clearenv() == 0, "clear worker environment");
        sysneed(setenv("KRB5_CONFIG", "/etc/craft/krb5.conf", 1) == 0 &&
                    setenv("HOME", "/nonexistent", 1) == 0 && setenv("LANG", "C", 1) == 0,
                "set worker environment");
        no_core();
        signal(SIGALRM, SIG_DFL);
        alarm(90);
        struct rlimit cpu{30, 30}, mem{512 * 1024 * 1024, 512 * 1024 * 1024};
        sysneed(setrlimit(RLIMIT_CPU, &cpu) == 0 && setrlimit(RLIMIT_AS, &mem) == 0,
                "worker resource limits");
        const Account svc = service_account();
        need(getuid() == svc.uid && geteuid() == svc.uid && getgid() == svc.gid && getegid() == svc.gid,
             "worker must run with dedicated account credentials");

        // Balance curl process initialization across every normal or exceptional exit.
        need(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK, "curl initialize");
        ScopeExit cleanup_curl([]() noexcept { curl_global_cleanup(); });

        // Re-resolve the runtime UID, validate account, and rate-limit enrollment.
        requesting_uid = number(argv[1]);
        const std::string name = argv[2];
        need(requesting_uid != 0 && requesting_uid != svc.uid && simple_name(name),
             "invalid requesting account");
        need(lookup_uid(requesting_uid).name == name,
             "runtime UID/name changed; administrator review required");
        Config cfg = config();
        Fd lock = rate_limit(requesting_uid, cfg.interval);
        root_open(path("kdc-trust.pem"));
        root_open(path("kdc-crls.pem"));

        // Verify the agent, then enroll a fresh certificate for the fixed identity.
        Cert agent = load_cert("agent.pem");
        Key agent_key = load_key("agent.key");
        need(has_eku(agent.get(), AGENT_OID), "agent certificate lacks Certificate Request Agent EKU");
        sslneed(X509_check_private_key(agent.get(), agent_key.get()) == 1, "agent key mismatch");
        verify_chain(agent.get());
        Kerberos krb;
        krb.acquire_transport(cfg);
        Mapping m = lookup_ad_user(cfg, requesting_uid, name);
        const auto cn = common_name(cfg, name, m.upn);
        Key user_key = generate_key();
        Req req = make_request(user_key.get(), m.upn, cfg.template_oid, cn);
        Bytes cms = wrap_eobo(req.get(), agent.get(), agent_key.get(), cfg.netbios + "\\" + name);
        std::string response = send_ces(cfg, soap_request(cfg, cms));
        Cert user_cert = parse_response(response, user_key.get());

        // Validate the issued identity before requesting and returning the TGT.
        verify_chain(user_cert.get());
        time_t end = validate_leaf(user_cert.get(), user_key.get(), m, cfg);
        Bytes result = get_tgt(krb, cfg, m, user_cert.get(), user_key.get(), end);
        ScopeExit erase([&]() noexcept { wipe(result); });
        openlog("craft", LOG_PID, LOG_AUTHPRIV);
        syslog(LOG_NOTICE,
               "issued TGT uid=%lu user=%s certificate_expiry=%lld",
               static_cast<unsigned long>(m.uid),
               m.name.c_str(),
               static_cast<long long>(end));
        closelog();
        write_all(STDOUT_FILENO, result);
        return 0;
    }
    catch (const std::exception &e)
    {
        openlog("craft", LOG_PID, LOG_AUTHPRIV);
        syslog(LOG_WARNING, "failed uid=%lu: %s", static_cast<unsigned long>(requesting_uid), e.what());
        closelog();
        std::cerr << "craft-worker: " << safe_message(e.what()) << '\n';
        return 1;
    }
}
#endif
