// Unprivileged certificate worker. The public entry point is launcher.cpp.
#include "common.hpp"
#include <sys/mman.h>
#include <sys/file.h>
#include <signal.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
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

enum class CertificateSource { Enrollment, Home, KeyTrust };

struct Config
{
    std::string domain, realm, netbios, template_oid, ces_url, ces_auth, service_principal;
    std::string certificate_cn = "{user}";
    std::string gc_url, gc_base_dn;
    uint32_t tgt = 36000, renew = 604800, cert_remaining = 36000, cert_total = 36000, interval = 60;
    bool require_full_tgt_lifetime = true;
    std::string mechanism = "enrollment", kt_dc_url;
    CertificateSource source = CertificateSource::Enrollment;
};

// Parse a strict configuration independently of privileged file access.
inline Config parse_config(std::string_view text, CertificateSource source = CertificateSource::Enrollment)
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
                                        "mechanism",
                                        "kt_dc_url",
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

    // The caller's hint selects home versus the privileged fallback; configuration picks the fallback mechanism.
    std::string mechanism = "enrollment";
    if (source != CertificateSource::Home)
    {
        if (v.contains("mechanism")) mechanism = v["mechanism"];
        need(mechanism == "enrollment" || mechanism == "key_trust",
             "mechanism must be enrollment or key_trust");
        source = mechanism == "key_trust" ? CertificateSource::KeyTrust : CertificateSource::Enrollment;
    }
    const bool directory = source != CertificateSource::Home;         // service account and LDAP/GSSAPI
    const bool enrollment = source == CertificateSource::Enrollment;  // CA, CES and enrollment agent
    const bool key_trust = source == CertificateSource::KeyTrust;     // msDS-KeyCredentialLink
    const auto when = [&](bool required, const char *key)
    {
        return required ? get(key) : std::string{};
    };
    Config c;
    c.domain = get("domain");
    c.realm = get("realm");
    c.netbios = when(enrollment, "netbios");
    c.template_oid = when(enrollment, "template_oid");
    c.ces_url = when(enrollment, "ces_url");
    c.ces_auth = when(enrollment, "ces_auth");
    c.service_principal = when(directory, "service_principal");
    c.mechanism = mechanism;
    c.kt_dc_url = when(key_trust, "kt_dc_url");
    c.source = source;

    // Validate domain syntax and length limits using regex
    need(c.domain.size() < 254 && c.realm.size() < 254 && c.netbios.size() <= 15, "domain value too long");
    const static std::regex domain_re(
        R"(^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$)");
    const static std::regex realm_re(
        R"(^[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)*$)");
    const static std::regex netbios_re(R"(^[A-Z0-9_-]+$)");
    need(std::regex_match(c.domain, domain_re), "domain must be lowercase DNS syntax");
    need(std::regex_match(c.realm, realm_re), "realm must be uppercase DNS syntax");
    if (enrollment)
    {
        need(std::regex_match(c.netbios, netbios_re), "invalid NetBIOS domain");
        Obj oid(OBJ_txt2obj(c.template_oid.c_str(), 1));
        sslneed(oid != nullptr, "invalid template OID");
        need(c.ces_auth == "negotiate" || c.ces_auth == "mtls", "ces_auth must be negotiate or mtls");
    }
    if (key_trust)
        need((c.kt_dc_url.starts_with("ldap://") || c.kt_dc_url.starts_with("ldaps://")) &&
                 c.kt_dc_url.size() < 256,
             "kt_dc_url must be an ldap:// or ldaps:// URL for the writable domain controller");
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

inline Config config(CertificateSource source = CertificateSource::Enrollment)
{
    return parse_config(root_text(path("config")), source);
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

struct UserIdentity
{
    Cert certificate;
    Key key;
};

inline UserIdentity load_user_identity(const UserIdentityFiles &files)
{
    // Keep private-key bytes bounded and erase them on normal and exceptional exits.
    const Bytes certificate_bytes = read_all(files.certificate.get());
    Bytes key_bytes = read_all(files.key.get());
    ScopeExit erase([&]() noexcept { wipe(key_bytes); });

    // Never prompt for a private-key passphrase in an unattended Kerberos operation.
    Bio certificate = membio(certificate_bytes), key = membio(key_bytes);
    UserIdentity identity{Cert(PEM_read_bio_X509(certificate.get(), nullptr, nullptr, nullptr)),
                          Key(PEM_read_bio_PrivateKey(key.get(), nullptr, no_pem_password, nullptr))};
    sslneed(identity.certificate && identity.key,
            "read ~/.config/craft/user.pem and unencrypted PEM user.key");
    return identity;
}

inline Key generate_key(int bits = 3072)
{
    Owned<EVP_PKEY_CTX, EVP_PKEY_CTX_free> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    sslneed(ctx && EVP_PKEY_keygen_init(ctx.get()) > 0 &&
                EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) > 0,
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

// --- Key Trust (msDS-KeyCredentialLink) credential construction, per MS-ADTS 2.2.20. ---

inline Bytes sha256(ByteView data)
{
    Bytes digest(SHA256_DIGEST_LENGTH);
    unsigned length = 0;
    Owned<EVP_MD_CTX, EVP_MD_CTX_free> ctx(EVP_MD_CTX_new());
    sslneed(ctx && EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1 &&
                EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 1 &&
                EVP_DigestFinal_ex(ctx.get(), digest.data(), &length) == 1 && length == digest.size(),
            "SHA-256 digest");
    return digest;
}

inline void le16(Bytes &b, uint16_t value)
{
    b.push_back(static_cast<unsigned char>(value));
    b.push_back(static_cast<unsigned char>(value >> 8));
}

inline void le32(Bytes &b, uint32_t value)
{
    for (int shift = 0; shift < 32; shift += 8) b.push_back(static_cast<unsigned char>(value >> shift));
}

inline void le64(Bytes &b, uint64_t value)
{
    for (int shift = 0; shift < 64; shift += 8) b.push_back(static_cast<unsigned char>(value >> shift));
}

// Serialize an RSA public key as a CNG BCRYPT_RSAPUBLIC_BLOB ("RSA1"); this is the Key Trust key material.
inline Bytes rsa_public_blob(EVP_PKEY *key)
{
    need(EVP_PKEY_base_id(key) == EVP_PKEY_RSA, "Key Trust requires an RSA key");
    Owned<BIGNUM, BN_free> modulus, exponent;
    sslneed(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, out(modulus)) == 1 &&
                EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, out(exponent)) == 1,
            "read RSA public parameters");
    const int mod_len = BN_num_bytes(modulus.get()), exp_len = BN_num_bytes(exponent.get());
    sslneed(mod_len > 0 && exp_len > 0, "RSA parameter length");
    Bytes blob{'R', 'S', 'A', '1'};
    le32(blob, static_cast<uint32_t>(BN_num_bits(modulus.get())));
    le32(blob, static_cast<uint32_t>(exp_len));
    le32(blob, static_cast<uint32_t>(mod_len));
    le32(blob, 0); // cbPrime1
    le32(blob, 0); // cbPrime2
    const size_t header = blob.size();
    blob.resize(header + static_cast<size_t>(exp_len) + static_cast<size_t>(mod_len));
    sslneed(BN_bn2bin(exponent.get(), blob.data() + header) == exp_len &&
                BN_bn2bin(modulus.get(), blob.data() + header + exp_len) == mod_len,
            "encode RSA public blob");
    return blob;
}

// Build a version-2 Key Credential Link blob advertising a single NGC (Key Trust) key.
inline Bytes key_credential_blob(EVP_PKEY *key, ByteView device_id, time_t now)
{
    need(device_id.size() == 16, "device identifier must be a 16-byte GUID");
    const auto entry = [](Bytes &b, unsigned char identifier, ByteView value)
    {
        need(value.size() <= 0xffff, "key credential entry too large");
        le16(b, static_cast<uint16_t>(value.size()));
        b.push_back(identifier);
        b.insert(b.end(), value.begin(), value.end());
    };
    const Bytes material = rsa_public_blob(key);
    const uint64_t filetime = (static_cast<uint64_t>(now) + 11644473600ULL) * 10000000ULL;
    Bytes stamp;
    le64(stamp, filetime);

    // KeyHash covers every entry following it; build that tail first, then prepend KeyID and KeyHash.
    Bytes tail;
    entry(tail, 0x03, material);          // KeyMaterial
    entry(tail, 0x04, Bytes{0x01});       // KeyUsage = NGC
    entry(tail, 0x05, Bytes{0x00});       // KeySource = Active Directory
    entry(tail, 0x06, device_id);         // DeviceId
    entry(tail, 0x07, Bytes{0x01, 0x02}); // CustomKeyInformation: Version 1, MFA_NOT_USED
    entry(tail, 0x08, stamp);             // KeyApproximateLastLogonTimeStamp
    entry(tail, 0x09, stamp);             // KeyCreationTime

    Bytes blob;
    le32(blob, 0x00000200);              // Version 2
    entry(blob, 0x01, sha256(material)); // KeyID = SHA-256(KeyMaterial)
    entry(blob, 0x02, sha256(tail));     // KeyHash = SHA-256(subsequent entries)
    blob.insert(blob.end(), tail.begin(), tail.end());
    return blob;
}

// Represent the blob as the DN-Binary value stored in msDS-KeyCredentialLink.
inline std::string dn_binary(ByteView blob, const std::string &dn)
{
    need(!dn.empty() && dn.find_first_of("\r\n") == std::string::npos, "invalid key credential object DN");
    constexpr std::string_view hex = "0123456789ABCDEF";
    std::string text;
    text.reserve(blob.size() * 2);
    for (unsigned char byte : blob)
    {
        text += hex[byte >> 4];
        text += hex[byte & 15];
    }
    return std::format("B:{}:{}:{}", text.size(), text, dn);
}

struct KeyTrustPair
{
    Cert leaf;
    Cert ca;
};

// Build a short-lived PKINIT leaf issued by an ephemeral local CA so MIT Kerberos includes the leaf in CMS SignedData.
inline KeyTrustPair make_key_trust_pair(EVP_PKEY *key, const std::string &cn, const std::string &upn, uint32_t validity)
{
    Key ca_key = generate_key(2048);
    Cert ca(X509_new());
    sslneed(ca && X509_set_version(ca.get(), 2) == 1, "CA initialize");
    Bytes ca_serial = random_bytes(16);
    ca_serial[0] &= 0x7f;
    Owned<BIGNUM, BN_free> ca_bn(BN_bin2bn(ca_serial.data(), static_cast<int>(ca_serial.size()), nullptr));
    sslneed(ca_bn && BN_to_ASN1_INTEGER(ca_bn.get(), X509_get_serialNumber(ca.get())) != nullptr, "CA serial");
    sslneed(X509_gmtime_adj(X509_getm_notBefore(ca.get()), -300) != nullptr &&
                X509_gmtime_adj(X509_getm_notAfter(ca.get()), static_cast<long>(validity + 3600)) != nullptr,
            "CA validity");
    Owned<X509_NAME, X509_NAME_free> ca_name(X509_NAME_new());
    sslneed(ca_name && X509_NAME_add_entry_by_txt(ca_name.get(), "CN", MBSTRING_ASC,
                                                  reinterpret_cast<const unsigned char *>("CRAFT Key Trust CA"),
                                                  -1, -1, 0) == 1,
            "CA subject");
    sslneed(X509_set_subject_name(ca.get(), ca_name.get()) == 1 &&
                X509_set_issuer_name(ca.get(), ca_name.get()) == 1 && X509_set_pubkey(ca.get(), ca_key.get()) == 1,
            "CA identity");
    const auto add_ca = [&](Ext e)
    {
        sslneed(e && X509_add_ext(ca.get(), e.get(), -1) == 1, "CA extension");
    };
    add_ca(Ext(X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_basic_constraints, const_cast<char *>("critical,CA:TRUE"))));
    add_ca(Ext(X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_key_usage, const_cast<char *>("critical,keyCertSign,cRLSign"))));
    sslneed(X509_sign(ca.get(), ca_key.get(), EVP_sha256()) > 0, "CA sign");

    Cert c(X509_new());
    sslneed(c && X509_set_version(c.get(), 2) == 1, "leaf initialize");
    Bytes serial = random_bytes(16);
    serial[0] &= 0x7f;
    Owned<BIGNUM, BN_free> bn(BN_bin2bn(serial.data(), static_cast<int>(serial.size()), nullptr));
    sslneed(bn && BN_to_ASN1_INTEGER(bn.get(), X509_get_serialNumber(c.get())) != nullptr, "leaf serial");
    sslneed(X509_gmtime_adj(X509_getm_notBefore(c.get()), -300) != nullptr &&
                X509_gmtime_adj(X509_getm_notAfter(c.get()), static_cast<long>(validity)) != nullptr,
            "leaf validity");
    Owned<X509_NAME, X509_NAME_free> name(X509_NAME_new());
    sslneed(name && X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                                               reinterpret_cast<const unsigned char *>(cn.data()),
                                               static_cast<int>(cn.size()), -1, 0) == 1,
            "leaf subject");
    sslneed(X509_set_subject_name(c.get(), name.get()) == 1 &&
                X509_set_issuer_name(c.get(), ca_name.get()) == 1 && X509_set_pubkey(c.get(), key) == 1,
            "leaf identity");
    const auto add = [&](Ext e)
    {
        sslneed(e && X509_add_ext(c.get(), e.get(), -1) == 1, "leaf extension");
    };
    Bytes text(upn.begin(), upn.end());
    add(raw_extension("2.5.29.17", der(0x30, der(0xa0, join(oid_der(UPN_OID), der(0xa0, der(0x0c, text)))))));
    add(Ext(X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_basic_constraints, const_cast<char *>("critical,CA:FALSE"))));
    add(Ext(X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_key_usage, const_cast<char *>("critical,digitalSignature"))));
    add(Ext(X509V3_EXT_conf_nid(nullptr,
                                nullptr,
                                NID_ext_key_usage,
                                const_cast<char *>("clientAuth,1.3.6.1.4.1.311.20.2.2,1.3.6.1.5.2.3.4"))));
    sslneed(X509_sign(c.get(), ca_key.get(), EVP_sha256()) > 0, "leaf signature");
    return {std::move(c), std::move(ca)};
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
inline std::vector<std::string> certificate_ekus(X509 *cert)
{
    int critical{};
    Owned<EXTENDED_KEY_USAGE, EXTENDED_KEY_USAGE_free> usages(
        static_cast<EXTENDED_KEY_USAGE *>(X509_get_ext_d2i(cert, NID_ext_key_usage, &critical, nullptr)));
    if (!usages) return {};
    std::vector<std::string> result;
    const int count = sk_ASN1_OBJECT_num(usages.get());
    result.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i)
        result.push_back(objtext(sk_ASN1_OBJECT_value(usages.get(), i)));
    return result;
}

inline bool has_eku(X509 *cert, const std::string &oid)
{
    const auto ekus = certificate_ekus(cert);
    return std::ranges::find(ekus, oid) != ekus.end();
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

// Enforce logon identity and usage; enrollment additionally pins the template and short validity.
inline time_t validate_leaf(X509 *c, EVP_PKEY *key, const Mapping &m, const Config &cfg,
                           CertificateSource source = CertificateSource::Enrollment)
{
    sslneed(X509_check_private_key(c, key) == 1, "user certificate public key mismatch");
    int bc_critical{};
    Owned<BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free> bc(
        static_cast<BASIC_CONSTRAINTS *>(X509_get_ext_d2i(c, NID_basic_constraints, &bc_critical, nullptr)));
    need(bc && !bc->ca && !bc->pathlen && X509_check_ca(c) == 0, "user certificate needs CA:FALSE");
    const auto ekus = certificate_ekus(c);
    const auto has = [&](std::string_view oid)
    {
        return std::ranges::find(ekus, oid) != ekus.end();
    };
    if (source == CertificateSource::Enrollment)
        need(has(SMARTCARD_OID) && has(CLIENT_AUTH_OID) && has(PKINIT_CLIENT_OID),
             "issued certificate needs Smart Card Logon, Client Authentication and PKINIT Client Authentication "
             "EKUs");
    else
        need(has(SMARTCARD_OID) || has(PKINIT_CLIENT_OID),
             "certificate needs Smart Card Logon or PKINIT Client Authentication EKU");
    int critical = 0;
    Owned<ASN1_BIT_STRING, ASN1_BIT_STRING_free> ku(
        static_cast<ASN1_BIT_STRING *>(X509_get_ext_d2i(c, NID_key_usage, &critical, nullptr)));
    need(ku && ASN1_BIT_STRING_get_bit(ku.get(), 0) == 1 && !ASN1_BIT_STRING_get_bit(ku.get(), 5) &&
             !ASN1_BIT_STRING_get_bit(ku.get(), 6),
         "certificate needs digitalSignature and must not authorize certificate/CRL signing");
    const auto upn = certificate_upn(c);
    time_t now = time(nullptr), start = as_time(X509_get0_notBefore(c)), end = as_time(X509_get0_notAfter(c));
    need(start <= now && end > now + 60, "certificate is not currently valid for at least 60 seconds");
    if (source != CertificateSource::Home)
    {
        const std::string expected_upn = m.upn.empty() ? (m.name + "@" + cfg.domain) : m.upn;
        need(upn == expected_upn, "certificate UPN differs from the directory userPrincipalName");
    }
    if (source == CertificateSource::Enrollment)
    {
        need(certificate_template(c) == cfg.template_oid, "CA returned the wrong certificate template");
        need(end - start > 0 && end - start <= cfg.cert_total,
             "CA issued a certificate with excessive total validity");
        need(end - now <= cfg.cert_remaining,
             "CA issued a certificate with excessive remaining validity; configure the short-lived template");
    }
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
    const std::string id = random_uuid();

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

inline std::string safe_message(std::string_view s)
{
    return sanitize_ascii(s);
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

    void check(krb5_error_code code, std::string_view operation) const
    {
        krb_check(ctx(), code, operation);
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
    need((creds.ticket_flags & TKT_FLG_PRE_AUTH) && (creds.ticket_flags & TKT_FLG_INITIAL) &&
             !(creds.ticket_flags & PROHIBITED_TKT_FLAGS),
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
get_tgt(Kerberos &k, const Config &cfg, const Mapping &m, X509 *cert, EVP_PKEY *key, time_t cert_end, X509 *ca = nullptr)
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
    erase_key.release();
    clear_key_bio();
    erase_bio.release();
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
    Fd anchor_fd;
    std::string anchor_str = "FILE:" + path("kdc-trust.pem");
    if (ca != nullptr)
    {
        Bio cabio(BIO_new(BIO_s_mem()));
        sslneed(cabio && PEM_write_bio_X509(cabio.get(), ca) == 1, "serialize CA anchor");
        Bytes cab = biobytes(cabio.get());
        std::string anchor_data = root_text(path("kdc-trust.pem"));
        anchor_data.append(reinterpret_cast<const char *>(cab.data()), cab.size());
        anchor_fd = memory_file("craft-anchors", byte_view(anchor_data));
        anchor_str = std::format("FILE:/proc/self/fd/{}", anchor_fd.get());
    }
    k.check(krb5_get_init_creds_opt_set_pa(
                k.ctx(), opts.get(), "X509_anchors", anchor_str.c_str()),
            "set KDC trust anchors");

    // NULL password plus refusing all prompts: no password/keytab fallback for users.
    k.check(
        krb5_get_init_creds_password(
            k.ctx(), &creds, principal.get(), nullptr, refuse_prompt, nullptr, 0, nullptr, opts.get()),
        "user PKINIT");
    validate_tgt(k.ctx(), cfg, creds, principal.get(), tgs.get(), requested_at, time(nullptr));
    const auto outer = ticket_enctype(k.ctx(), creds.ticket);
    const auto renew_str = creds.times.renew_till > 0
        ? std::format(" (renewable until Unix {})", creds.times.renew_till)
        : "";
    std::cerr << std::format(
        "craft-worker: TGT expires at Unix {}{}; session enctype={}; ticket enctype={}\n",
        creds.times.endtime,
        renew_str,
        creds.keyblock.enctype,
        outer);
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
    write_truncated(f.get(), byte_view(t));
    return f;
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

// Establish an integrity-protected LDAP connection bound as the directory service account.
inline ScopedLdap ldap_connect(const std::string &url)
{
    ScopedLdap ld;
    int rc = ldap_initialize(out(ld), url.c_str());
    need(rc == LDAP_SUCCESS && ld,
         std::format("LDAP initialize failed for {}: {}", url, ldap_err2string(rc)));
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
    need(rc == LDAP_SUCCESS, std::format("LDAP GSSAPI bind failed to {}: {}", url, ldap_err2string(rc)));
    return ld;
}

// Resolve the caller's unique directory object, returning its distinguished name and userPrincipalName.
inline Mapping directory_lookup(LDAP *ld, const Config &cfg, const std::string &base_dn, uid_t uid,
                                const std::string &name)
{
    need(simple_name(name), "invalid username for directory query");
    struct timeval tv{10, 0};
    std::string filter = std::format("(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))", name);
    const char *attrs[] = {"userPrincipalName", cfg.source == CertificateSource::KeyTrust ? "objectGUID" : nullptr,
                           nullptr};
    ScopedLdapMsg res;
    int rc = ldap_search_ext_s(ld, base_dn.c_str(), LDAP_SCOPE_SUBTREE, filter.c_str(),
                               const_cast<char **>(attrs), 0, nullptr, nullptr, &tv, 2, out(res));
    need(rc == LDAP_SUCCESS && res, std::format("LDAP search failed: {}", ldap_err2string(rc)));

    int count = ldap_count_entries(ld, res.get());
    need(count > 0, std::format("user '{}' not found in Active Directory", name));
    need(count == 1, std::format("ambiguous user '{}': multiple Active Directory entries found", name));

    LDAPMessage *entry = ldap_first_entry(ld, res.get());
    need(entry != nullptr, "failed to get LDAP entry");
    Owned<char, ldap_memfree> dn(ldap_get_dn(ld, entry));
    need(dn && *dn.get(), "Active Directory entry has no distinguished name");

    Owned<berval *, ldap_value_free_len> upn_vals(ldap_get_values_len(ld, entry, "userPrincipalName"));
    need(!upn_vals || ldap_count_values_len(upn_vals.get()) <= 1,
         "Active Directory entry has multiple userPrincipalName values");
    const auto *upn = upn_vals ? *upn_vals : nullptr;
    const auto upn_str = upn && upn->bv_len ? std::string(upn->bv_val, upn->bv_len) : name + "@" + cfg.domain;
    Mapping mapping{.uid = uid, .name = name, .upn = upn_str, .dn = std::string(dn.get())};
    if (cfg.source == CertificateSource::KeyTrust)
    {
        // Address both the account and its DN-Binary reference by immutable GUID across moves and renames.
        Owned<berval *, ldap_value_free_len> guids(ldap_get_values_len(ld, entry, "objectGUID"));
        need(guids && ldap_count_values_len(guids.get()) == 1 && guids.get()[0]->bv_len == 16,
             "Active Directory entry has no valid objectGUID");
        mapping.object_ref = "<GUID=";
        for (size_t i = 0; i < 16; ++i)
            mapping.object_ref += std::format("{:02x}", static_cast<unsigned char>(guids.get()[0]->bv_val[i]));
        mapping.object_ref += ">";
    }
    return mapping;
}

inline Mapping lookup_ad_user(const Config &cfg, uid_t uid, const std::string &name)
{
    const auto ld = ldap_connect(cfg.gc_url);
    const auto base_dn = cfg.gc_base_dn.empty() ? domain_to_dn(cfg.domain) : cfg.gc_base_dn;
    return directory_lookup(ld.get(), cfg, base_dn, uid, name);
}

// Add or remove exactly one Key Trust value, leaving any other key credentials on the object untouched.
inline void modify_key_credential(LDAP *ld, const std::string &dn, const std::string &value, bool add)
{
    std::string editable = value;
    char *values[] = {editable.data(), nullptr};
    LDAPMod mod{};
    mod.mod_op = add ? LDAP_MOD_ADD : LDAP_MOD_DELETE;
    mod.mod_type = const_cast<char *>("msDS-KeyCredentialLink");
    mod.mod_values = values;
    LDAPMod *mods[] = {&mod, nullptr};
    const int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    if (!add && rc == LDAP_NO_SUCH_ATTRIBUTE) return;
    need(rc == LDAP_SUCCESS,
         std::format("{} msDS-KeyCredentialLink failed: {}", add ? "add" : "remove", ldap_err2string(rc)));
}

// Retry cleanup with a fresh connection and report a residual credential if the directory remains unavailable.
inline bool detach_key_credential(const Config &cfg, LDAP *ld, const std::string &dn,
                                  const std::string &value) noexcept
{
    try
    {
        modify_key_credential(ld, dn, value, false);
        return true;
    }
    catch (const std::exception &)
    {
        // The live connection may have failed; fall through to a fresh bind before giving up.
    }
    try
    {
        const auto fresh = ldap_connect(cfg.kt_dc_url);
        modify_key_credential(fresh.get(), dn, value, false);
        return true;
    }
    catch (const std::exception &error)
    {
        openlog("craft", LOG_PID, LOG_AUTHPRIV);
        syslog(LOG_CRIT,
               "CRITICAL: could not remove temporary msDS-KeyCredentialLink from %s; remove it manually (%s)",
               dn.c_str(), error.what());
        closelog();
        std::cerr << "craft-worker: CRITICAL: failed to remove the temporary key credential from "
                  << sanitize_ascii(dn) << "; remove it manually\n";
    }
    return false;
}

// Arm independent cleanup before attempting the write, including writes whose LDAP response is lost.
inline Fd start_key_credential_cleanup(const Config &cfg, const std::string &object_ref,
                                      const std::string &value, pid_t &child, int lock_fd)
{
    std::array<int, 2> control{}, ready{};
    sysneed(pipe2(control.data(), O_CLOEXEC) == 0, "key cleanup pipe");
    Fd reader(control[0]), trigger(control[1]);
    sysneed(pipe2(ready.data(), O_CLOEXEC) == 0, "key cleanup readiness pipe");
    Fd ready_reader(ready[0]), ready_writer(ready[1]);
    child = fork();
    sysneed(child >= 0, "key cleanup fork");
    if (child == 0)
    {
        try
        {
            // Survive worker alarms, terminal signals and launcher death while retaining the issuance lock.
            alarm(0);
            sysneed(prctl(PR_SET_PDEATHSIG, 0) == 0, "key cleanup parent-death signal");
            for (int signum : {SIGALRM, SIGINT, SIGTERM, SIGHUP, SIGPIPE, SIGXCPU})
                sysneed(signal(signum, SIG_IGN) != SIG_ERR, "key cleanup signal disposition");
            const int saved_lock = lock_fd >= 0 ? fcntl(lock_fd, F_DUPFD_CLOEXEC, 6) : -1;
            sysneed(lock_fd < 0 || saved_lock >= 0, "key cleanup lock duplicate");
            sysneed(dup2(reader.get(), 3) == 3 && dup2(ready_writer.get(), 4) == 4,
                    "key cleanup descriptors");
            if (saved_lock >= 0) sysneed(dup2(saved_lock, 5) == 5, "key cleanup lock");
            else (void)close(5);
            close_from(6);
            const Fd null(open("/dev/null", O_RDWR));
            sysneed(null.get() >= 0 && dup2(null.get(), STDIN_FILENO) == STDIN_FILENO &&
                        dup2(null.get(), STDOUT_FILENO) == STDOUT_FILENO,
                    "key cleanup standard descriptors");

            // Bind our own connection; inherited LDAP sockets must never be shared after fork.
            const auto ld = ldap_connect(cfg.kt_dc_url);
            const unsigned char armed = 1;
            write_all(4, {&armed, 1});
            (void)close(4);
            unsigned char ignored;
            ssize_t count;
            do { count = read(3, &ignored, 1); } while (count < 0 && errno == EINTR);
            const bool removed = detach_key_credential(cfg, ld.get(), object_ref, value);
            _exit(removed ? 0 : 1);
        }
        catch (const std::exception &error)
        {
            openlog("craft", LOG_PID, LOG_AUTHPRIV);
            syslog(LOG_CRIT, "key cleanup failed for %s: %s", object_ref.c_str(), error.what());
            closelog();
            _exit(1);
        }
    }
    reader = Fd();
    ready_writer = Fd();
    const auto armed = read_all(ready_reader.get(), 1);
    need(armed == Bytes{1}, "key cleanup process could not be armed");
    return trigger;
}

// Release credentials only after the independent process confirms successful removal.
inline void finish_key_credential_cleanup(Fd &trigger, pid_t &child)
{
    trigger = Fd();
    int status{};
    const pid_t pid = std::exchange(child, -1);
    sysneed(waitpid_retry(pid, &status) == pid, "wait for key cleanup");
    need(WIFEXITED(status) && WEXITSTATUS(status) == 0,
         "temporary key credential cleanup failed; existing cache was not replaced");
}
} // namespace craft

#ifndef CRAFT_TEST
int main(int argc, char **argv)
{
    using namespace craft;
    uid_t requesting_uid = 0;
    try
    {
        // Reset inherited state and select the caller or dedicated-account workflow.
        const bool home = argc == 4 && std::string_view(argv[1]) == "--home";
        need(home || argc == 3, "worker is not a public interface; use craft");
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

        // Re-resolve the runtime UID and validate the requesting account.
        requesting_uid = number(argv[home ? 2 : 1]);
        const std::string name = argv[home ? 3 : 2];
        need(requesting_uid != 0 && simple_name(name), "invalid requesting account");
        const Account caller = lookup_uid(requesting_uid);
        need(caller.name == name,
             "runtime UID/name changed; administrator review required");
        UserIdentityFiles files;
        if (home)
        {
            // Report selection before returning credentials so the launcher can relinquish root.
            need(getuid() == requesting_uid && geteuid() == requesting_uid && getgid() == getegid(),
                 "home certificate worker must run as the caller");
            files = user_identity_files(caller);
            const unsigned char selected = files.certificate.get() >= 0;
            write_all(STDOUT_FILENO, {&selected, 1});
            if (!selected) return 0;
        }
        else
        {
            // Restrict the privileged fallback (enrollment or Key Trust) to the dedicated account.
            const Account svc = service_account();
            need(requesting_uid != svc.uid && getuid() == svc.uid && geteuid() == svc.uid &&
                     getgid() == svc.gid && getegid() == svc.gid,
                 "privileged worker must run with dedicated account credentials");
        }

        // Resolve the configuration first; it selects the fallback mechanism when no home pair is present.
        Config cfg = config(home ? CertificateSource::Home : CertificateSource::Enrollment);
        const CertificateSource source = cfg.source;

        // Only CA enrollment uses libcurl/CES; balance its initialization across normal and exceptional exits.
        if (source == CertificateSource::Enrollment)
            need(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK, "curl initialize");
        ScopeExit cleanup_curl([source]() noexcept
                               { if (source == CertificateSource::Enrollment) curl_global_cleanup(); });

        Fd lock;
        if (!home) lock = rate_limit(requesting_uid, cfg.interval);
        root_open(path("kdc-trust.pem"));
        root_open(path("kdc-crls.pem"));

        // Keep the caller principal fixed; the KDC enforces certificate-to-account mapping in every mode.
        Kerberos krb;
        Mapping m{.uid = requesting_uid, .name = name, .upn = {}, .dn = {}};
        UserIdentity identity;
        Bytes result;
        ScopeExit erase([&]() noexcept { wipe(result); });
        time_t end = 0;
        {
            // Acquire and validate the certificate identity, publishing no Key Trust key beyond this scope.
            ScopedLdap kt_ld;
            Cert kt_ca;
            Fd kt_trigger;
            pid_t kt_cleanup_pid = -1;
            ScopeExit kt_cleanup([&]() noexcept
            {
                // Closing the pipe also triggers cleanup when acquisition throws.
                kt_trigger = Fd();
                if (kt_cleanup_pid > 0) (void)waitpid_retry(kt_cleanup_pid);
            });

            if (home)
            {
                identity = load_user_identity(files);
            }
            else if (source == CertificateSource::Enrollment)
            {
                // Verify the agent and enroll a fresh certificate for the fixed directory identity.
                Cert agent = load_cert("agent.pem");
                Key agent_key = load_key("agent.key");
                need(has_eku(agent.get(), AGENT_OID), "agent certificate lacks Certificate Request Agent EKU");
                sslneed(X509_check_private_key(agent.get(), agent_key.get()) == 1, "agent key mismatch");
                verify_chain(agent.get());
                krb.acquire_transport(cfg);
                m = lookup_ad_user(cfg, requesting_uid, name);
                const auto cn = common_name(cfg, name, m.upn);
                identity.key = generate_key();
                Req req = make_request(identity.key.get(), m.upn, cfg.template_oid, cn);
                Bytes cms = wrap_eobo(req.get(), agent.get(), agent_key.get(), cfg.netbios + "\\" + name);
                const std::string response = send_ces(cfg, soap_request(cfg, cms));
                identity.certificate = parse_response(response, identity.key.get());
            }
            else
            {
                // Key Trust: write a public key to the directory, authenticate, then remove it.
                krb.acquire_transport(cfg);
                kt_ld = ldap_connect(cfg.kt_dc_url);
                m = directory_lookup(kt_ld.get(), cfg, domain_to_dn(cfg.domain), requesting_uid, name);
                identity.key = generate_key(2048);
                auto pair = make_key_trust_pair(
                    identity.key.get(), common_name(cfg, name, m.upn), m.upn, cfg.tgt + 3600);
                identity.certificate = std::move(pair.leaf);
                kt_ca = std::move(pair.ca);
                const Bytes blob = key_credential_blob(identity.key.get(), Bytes(16, 0), time(nullptr));
                const std::string value = dn_binary(blob, m.object_ref);
                kt_trigger = start_key_credential_cleanup(cfg, m.object_ref, value, kt_cleanup_pid, lock.get());
                modify_key_credential(kt_ld.get(), m.object_ref, value, true);
            }

            // The Key Trust certificate is authorized by the directory write, not a CA chain.
            if (source != CertificateSource::KeyTrust) verify_chain(identity.certificate.get());
            end = validate_leaf(identity.certificate.get(), identity.key.get(), m, cfg, source);
            result = get_tgt(krb, cfg, m, identity.certificate.get(), identity.key.get(), end, kt_ca.get());

            // Remove the Key Trust key immediately, before any credential bytes leave this process.
            if (kt_cleanup_pid > 0) finish_key_credential_cleanup(kt_trigger, kt_cleanup_pid);
        }
        const char *origin = source == CertificateSource::Home       ? "home"
                             : source == CertificateSource::KeyTrust ? "key_trust"
                                                                     : "enrollment";
        openlog("craft", LOG_PID, LOG_AUTHPRIV);
        syslog(LOG_NOTICE,
               "issued TGT uid=%lu user=%s certificate_source=%s certificate_expiry=%lld",
               static_cast<unsigned long>(m.uid),
               m.name.c_str(),
               origin,
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
