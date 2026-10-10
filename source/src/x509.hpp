#pragma once

// OpenSSL ownership, bounded ASN.1 encoding, and the certificate identity and policy checks.
#include "config.hpp"
#include "resources.hpp"
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace craft
{
using Key = Owned<EVP_PKEY, EVP_PKEY_free>;
using Cert = Owned<X509, X509_free>;
using Bio = Owned<BIO, BIO_free>;
using Obj = Owned<ASN1_OBJECT, ASN1_OBJECT_free>;
using Ext = Owned<X509_EXTENSION, X509_EXTENSION_free>;
using Name = Owned<X509_NAME, X509_NAME_free>;
using BigNum = Owned<BIGNUM, BN_free>;

// Free OpenSSL stacks and their elements as one owned resource.
inline void free_extensions(STACK_OF(X509_EXTENSION) * p) noexcept
{
    sk_X509_EXTENSION_pop_free(p, X509_EXTENSION_free);
}

inline void free_certificates(STACK_OF(X509) * p) noexcept
{
    sk_X509_pop_free(p, X509_free);
}

inline void free_asn1_sequence(STACK_OF(ASN1_TYPE) * p) noexcept
{
    sk_ASN1_TYPE_pop_free(p, ASN1_TYPE_free);
}

using Extensions = Owned<STACK_OF(X509_EXTENSION), free_extensions>;
using Certificates = Owned<STACK_OF(X509), free_certificates>;
using Asn1Sequence = Owned<STACK_OF(ASN1_TYPE), free_asn1_sequence>;

inline constexpr char SAN_OID[] = "2.5.29.17";
inline constexpr char UPN_OID[] = "1.3.6.1.4.1.311.20.2.3";
inline constexpr char AGENT_OID[] = "1.3.6.1.4.1.311.20.2.1";
inline constexpr char SMARTCARD_OID[] = "1.3.6.1.4.1.311.20.2.2";
inline constexpr char TEMPLATE_OID[] = "1.3.6.1.4.1.311.21.7";
inline constexpr char PKINIT_CLIENT_OID[] = "1.3.6.1.5.2.3.4";
inline constexpr char CLIENT_AUTH_OID[] = "1.3.6.1.5.5.7.3.2";

#if OPENSSL_VERSION_NUMBER < 0x30000000L
// OpenSSL 1.1.1 (RHEL 8) names public-key comparison differently.
inline int EVP_PKEY_eq(const EVP_PKEY *a, const EVP_PKEY *b)
{
    return EVP_PKEY_cmp(a, b);
}
#endif

inline void sslneed(bool good, std::string_view what)
{
    if (good) return;
    const unsigned long e = ERR_get_error();
    char text[256]{};
    if (e) ERR_error_string_n(e, text, sizeof(text));
    fail(e ? std::format("{}: {}", what, text) : std::string(what));
}

inline std::string objtext(const ASN1_OBJECT *o)
{
    need(o != nullptr, "missing OID");
    char s[256];
    const int n = OBJ_obj2txt(s, sizeof(s), o, 1);
    need(n > 0 && n < static_cast<int>(sizeof(s)), "invalid OID");
    return s;
}

// Encode bounded ASN.1 structures by hand where OpenSSL has no typed builder.
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
        for (; n; n >>= 8)
            len.insert(len.begin(), static_cast<unsigned char>(n & 255));
        b.push_back(static_cast<unsigned char>(0x80 | len.size()));
        b = join(std::move(b), len);
    }
    return join(std::move(b), value);
}

inline Bytes oid_der(const std::string &oid)
{
    Obj o(OBJ_txt2obj(oid.c_str(), 1));
    sslneed(o != nullptr, "OID parse");
    const int n = i2d_ASN1_OBJECT(o.get(), nullptr);
    sslneed(n > 0, "OID length");
    Bytes b(static_cast<size_t>(n));
    auto p = b.data();
    sslneed(i2d_ASN1_OBJECT(o.get(), &p) == n, "OID DER");
    return b;
}

inline Bio membio(ByteView b)
{
    need(b.size() <= 8 * MAX_BLOB, "BIO too large");
    Bio bio(BIO_new_mem_buf(b.data(), static_cast<int>(b.size())));
    sslneed(bio != nullptr, "BIO allocate");
    return bio;
}

inline ByteView bioview(BIO *b)
{
    char *p = nullptr;
    const long n = BIO_get_mem_data(b, &p);
    need(n >= 0 && static_cast<size_t>(n) <= MAX_BLOB, "BIO size");
    return {reinterpret_cast<const unsigned char *>(p), static_cast<size_t>(n)};
}

// Never prompt for a private-key passphrase in an unattended Kerberos operation.
inline int no_pem_password(char *, int, int, void *)
{
    return 0;
}

inline Cert read_cert(ByteView pem)
{
    const Bio bio = membio(pem);
    return Cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

inline Key read_key(ByteView pem)
{
    const Bio bio = membio(pem);
    return Key(PEM_read_bio_PrivateKey(bio.get(), nullptr, no_pem_password, nullptr));
}

inline Cert load_cert(const char *file)
{
    const Fd f = root_open(path(file));
    Cert x = read_cert(read_all(f.get()));
    sslneed(x != nullptr, "read certificate");
    return x;
}

// Erase serialized private-key bytes on both success and exception paths.
inline Key load_key(const char *file)
{
    const Fd f = root_open(path(file), Trusted::Secret);
    Bytes b = read_all(f.get());
    ScopeExit erase([&]() noexcept { wipe(b); });
    Key k = read_key(b);
    sslneed(k != nullptr,
            "read noninteractive PEM private key (encrypted PEM needs a different key backend)");
    return k;
}

struct UserIdentityFiles
{
    Fd certificate{};
    Fd key{};
};

// Open an optional PEM pair under ~/.config/craft using only the caller's filesystem permissions.
inline UserIdentityFiles user_identity_files(const Account &caller)
{
    need(getuid() == caller.uid && geteuid() == caller.uid,
         "user certificate must be opened after dropping to the caller");
    Fd directory = caller_home(caller);
    bool safe_directory = true;

    // Resolve the fixed location without following user-controlled symlinks.
    for (const char *name : {".config", "craft"})
    {
        Fd next(openat(directory.get(), name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (next.get() < 0 && errno == ENOENT) return {};
        sysneed(next.get() >= 0, "open ~/.config/craft for user certificate");
        struct stat st
        {
        };
        sysneed(fstat(next.get(), &st) == 0, "stat user certificate directory");
        safe_directory = safe_directory && st.st_uid == caller.uid && !(st.st_mode & 0022);
        directory = std::move(next);
    }

    // Only an entirely absent pair selects the fallback; partial or unsafe inputs fail.
    off_t certificate_size = 0, key_size = 0;
    UserIdentityFiles files{
        open_private(
            directory.get(), "user.pem", O_RDONLY, "~/.config/craft/user.pem", 0022, &certificate_size),
        open_private(directory.get(), "user.key", O_RDONLY, "~/.config/craft/user.key", 0077, &key_size)};
    if (files.certificate.get() < 0 && files.key.get() < 0) return {};
    need(safe_directory,
         "user certificate directories must belong to caller and not be group/world-writable");
    need(files.certificate.get() >= 0 && files.key.get() >= 0,
         "incomplete user certificate pair; provide both ~/.config/craft/user.pem and user.key");
    need(certificate_size > 0 && key_size > 0, "user certificate and key must not be empty");
    return files;
}

struct UserIdentity
{
    Cert certificate;
    Key key;
};

inline UserIdentity load_user_identity(const UserIdentityFiles &files)
{
    const Bytes certificate = read_all(files.certificate.get());
    Bytes key = read_all(files.key.get());
    ScopeExit erase([&]() noexcept { wipe(key); });
    UserIdentity identity{read_cert(certificate), read_key(key)};
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

// Building blocks shared by the enrollment request and the Key Trust certificates.
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

inline Ext conf_extension(int nid, const std::string &value)
{
    Ext e(X509V3_EXT_conf_nid(nullptr, nullptr, nid, const_cast<char *>(value.c_str())));
    sslneed(e != nullptr, "extension configuration");
    return e;
}

// SubjectAltName holding one Microsoft UPN otherName, encoded as UTF8String.
inline Ext upn_extension(std::string_view upn)
{
    const auto name = join(oid_der(UPN_OID), der(0xa0, der(0x0c, byte_view(upn))));
    return raw_extension(SAN_OID, der(0x30, der(0xa0, name)));
}

inline Ext logon_eku_extension()
{
    return conf_extension(NID_ext_key_usage,
                          std::format("{},{},{}", CLIENT_AUTH_OID, SMARTCARD_OID, PKINIT_CLIENT_OID));
}

inline Name common_name_only(std::string_view cn)
{
    Name name(X509_NAME_new());
    sslneed(name && X509_NAME_add_entry_by_txt(name.get(),
                                               "CN",
                                               MBSTRING_ASC,
                                               reinterpret_cast<const unsigned char *>(cn.data()),
                                               static_cast<int>(cn.size()),
                                               -1,
                                               0) == 1,
            "certificate common name");
    return name;
}

// Read certificate extensions while rejecting absent or ambiguous identity bindings.
inline std::vector<std::string> certificate_ekus(X509 *cert)
{
    Owned<EXTENDED_KEY_USAGE, EXTENDED_KEY_USAGE_free> usages(
        static_cast<EXTENDED_KEY_USAGE *>(X509_get_ext_d2i(cert, NID_ext_key_usage, nullptr, nullptr)));
    std::vector<std::string> result;
    for (int i = 0; usages && i < sk_ASN1_OBJECT_num(usages.get()); ++i)
        result.push_back(objtext(sk_ASN1_OBJECT_value(usages.get(), i)));
    return result;
}

inline bool has_eku(X509 *cert, std::string_view oid)
{
    const auto ekus = certificate_ekus(cert);
    return std::ranges::find(ekus, oid) != ekus.end();
}

inline Bytes extension_bytes(X509 *x, const char *oid)
{
    Obj o(OBJ_txt2obj(oid, 1));
    sslneed(o != nullptr, "extension OID");
    const int i = X509_get_ext_by_OBJ(x, o.get(), -1);
    if (i < 0 || X509_get_ext_by_OBJ(x, o.get(), i) >= 0)
        fail(std::format("missing/duplicate certificate extension {}", oid));
    const ASN1_OCTET_STRING *d = X509_EXTENSION_get_data(X509_get_ext(x, i));
    return Bytes(ASN1_STRING_get0_data(d), ASN1_STRING_get0_data(d) + ASN1_STRING_length(d));
}

inline std::string certificate_upn(X509 *c)
{
    const Bytes b = extension_bytes(c, SAN_OID);
    const unsigned char *p = b.data();
    Owned<GENERAL_NAMES, GENERAL_NAMES_free> names(
        d2i_GENERAL_NAMES(nullptr, &p, static_cast<long>(b.size())));
    sslneed(names && p == b.data() + b.size(), "decode SAN");
    std::string upn;
    int count = 0;
    for (int i = 0; i < sk_GENERAL_NAME_num(names.get()); ++i)
    {
        const GENERAL_NAME *n = sk_GENERAL_NAME_value(names.get(), i);
        if (n->type != GEN_OTHERNAME || objtext(n->d.otherName->type_id) != UPN_OID) continue;
        const ASN1_TYPE *v = n->d.otherName->value;
        need(v->type == V_ASN1_UTF8STRING, "UPN must be UTF8String");
        upn.assign(reinterpret_cast<const char *>(ASN1_STRING_get0_data(v->value.utf8string)),
                   static_cast<size_t>(ASN1_STRING_length(v->value.utf8string)));
        ++count;
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
    struct tm t
    {
    };
    sslneed(ASN1_TIME_to_tm(a, &t) == 1, "certificate time");
    const time_t result = timegm(&t);
    need(result != -1, "invalid certificate timestamp");
    return result;
}

// Verify CA trust and revocation from administrator-supplied files, without online fetching.
inline void verify_chain(X509 *x)
{
    const auto trust = path("ca-trust.pem"), crls = path("ca-crls.pem");
    root_open(trust);
    root_open(crls);
    Owned<X509_STORE, X509_STORE_free> s(X509_STORE_new());
    sslneed(s && X509_STORE_load_locations(s.get(), trust.c_str(), nullptr) == 1, "load CA trust");
    X509_LOOKUP *lookup = X509_STORE_add_lookup(s.get(), X509_LOOKUP_file());
    sslneed(lookup && X509_load_crl_file(lookup, crls.c_str(), X509_FILETYPE_PEM) > 0, "load CRLs");
    sslneed(X509_STORE_set_flags(s.get(), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) == 1,
            "enable CRL checks");
    Owned<X509_STORE_CTX, X509_STORE_CTX_free> ctx(X509_STORE_CTX_new());
    sslneed(ctx && X509_STORE_CTX_init(ctx.get(), s.get(), x, nullptr) == 1, "X509 verify init");
    if (X509_verify_cert(ctx.get()) != 1)
        fail(std::format("certificate trust/revocation failed: {}",
                         X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx.get()))));
}

// The caller's directory identity: Linux name, userPrincipalName and, for Key Trust, a GUID object reference.
struct Mapping
{
    std::string name, upn, object_ref = {};
};

// Enforce logon identity and usage; enrollment additionally pins the template and short validity.
inline time_t validate_leaf(X509 *c,
                            EVP_PKEY *key,
                            const Mapping &m,
                            const Config &cfg,
                            CertificateSource source = CertificateSource::Enrollment)
{
    sslneed(X509_check_private_key(c, key) == 1, "user certificate public key mismatch");

    // An end-entity certificate may omit basicConstraints, as stock AD CS templates do; only supplied home
    // certificates rely on that. CRAFT's own template and the Key Trust leaf always state CA:FALSE.
    Owned<BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free> bc(
        static_cast<BASIC_CONSTRAINTS *>(X509_get_ext_d2i(c, NID_basic_constraints, nullptr, nullptr)));
    need(X509_check_ca(c) == 0 && (bc ? !bc->ca && !bc->pathlen : source == CertificateSource::Home),
         "user certificate needs CA:FALSE");
    const auto ekus = certificate_ekus(c);
    const auto has = [&](std::string_view oid)
    {
        return std::ranges::find(ekus, oid) != ekus.end();
    };
    if (source == CertificateSource::Enrollment)
        need(has(SMARTCARD_OID) && has(CLIENT_AUTH_OID) && has(PKINIT_CLIENT_OID),
             "issued certificate needs Smart Card Logon, Client Authentication and PKINIT Client "
             "Authentication EKUs");
    else
        need(has(SMARTCARD_OID) || has(PKINIT_CLIENT_OID),
             "certificate needs Smart Card Logon or PKINIT Client Authentication EKU");
    Owned<ASN1_BIT_STRING, ASN1_BIT_STRING_free> ku(
        static_cast<ASN1_BIT_STRING *>(X509_get_ext_d2i(c, NID_key_usage, nullptr, nullptr)));
    need(ku && ASN1_BIT_STRING_get_bit(ku.get(), 0) == 1 && !ASN1_BIT_STRING_get_bit(ku.get(), 5) &&
             !ASN1_BIT_STRING_get_bit(ku.get(), 6),
         "certificate needs digitalSignature and must not authorize certificate/CRL signing");
    const auto upn = certificate_upn(c);
    const time_t now = time(nullptr), start = as_time(X509_get0_notBefore(c)),
                 end = as_time(X509_get0_notAfter(c));
    need(start <= now && end > now + 60, "certificate is not currently valid for at least 60 seconds");

    // The KDC alone maps a supplied home certificate to its account; the fallbacks bind the directory UPN
    // here.
    if (source != CertificateSource::Home)
        need(upn == m.upn, "certificate UPN differs from the directory userPrincipalName");
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

} // namespace craft
