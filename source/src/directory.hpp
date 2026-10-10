#pragma once

// Active Directory over LDAP: the caller's directory identity and the temporary Key Trust credential.
#include "x509.hpp"
#include <ldap.h>
#include <sasl/sasl.h>
#include <syslog.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

namespace craft
{
inline void free_ldap(LDAP *ld) noexcept
{
    (void)ldap_unbind_ext_s(ld, nullptr, nullptr);
}

using ScopedLdap = Owned<LDAP, free_ldap>;
using LdapMessage = Owned<LDAPMessage, ldap_msgfree>;
using LdapValues = Owned<berval *, ldap_value_free_len>;

inline void audit(int priority, const std::string &message)
{
    openlog("craft", LOG_PID, LOG_AUTHPRIV);
    syslog(priority, "%s", message.c_str());
    closelog();
}

inline int ldap_sasl_interact(LDAP *, unsigned, void *, void *in) noexcept
{
    for (auto *interact = static_cast<sasl_interact_t *>(in); interact && interact->id != SASL_CB_LIST_END;
         ++interact)
    {
        interact->result = nullptr;
        interact->len = 0;
    }
    return LDAP_SUCCESS;
}

// Establish an integrity-protected connection bound as the directory service account. libldap's host name
// canonicalization stays enabled: the default Global Catalog URL names the domain, not one controller, and
// the GSSAPI mutual authentication that follows still proves the peer holds that controller's key.
inline ScopedLdap ldap_connect(const std::string &url)
{
    ScopedLdap ld;
    int rc = ldap_initialize(out(ld), url.c_str());
    if (rc != LDAP_SUCCESS || !ld)
        fail(std::format("LDAP initialize failed for {}: {}", url, ldap_err2string(rc)));
    const int version = LDAP_VERSION3;
    const ber_len_t min_ssf = 1;
    const timeval tv{10, 0};
    need(ldap_set_option(ld.get(), LDAP_OPT_PROTOCOL_VERSION, &version) == LDAP_OPT_SUCCESS &&
             ldap_set_option(ld.get(), LDAP_OPT_REFERRALS, LDAP_OPT_OFF) == LDAP_OPT_SUCCESS &&
             ldap_set_option(ld.get(), LDAP_OPT_NETWORK_TIMEOUT, &tv) == LDAP_OPT_SUCCESS &&
             ldap_set_option(ld.get(), LDAP_OPT_TIMEOUT, &tv) == LDAP_OPT_SUCCESS &&
             ldap_set_option(ld.get(), LDAP_OPT_X_SASL_SSF_MIN, &min_ssf) == LDAP_OPT_SUCCESS,
         "LDAP protocol, timeout or integrity options rejected");
    rc = ldap_sasl_interactive_bind_s(
        ld.get(), nullptr, "GSSAPI", nullptr, nullptr, LDAP_SASL_QUIET, ldap_sasl_interact, nullptr);
    if (rc != LDAP_SUCCESS) fail(std::format("LDAP GSSAPI bind failed to {}: {}", url, ldap_err2string(rc)));
    return ld;
}

// Resolve the caller's unique directory object: its userPrincipalName and, for Key Trust, its objectGUID.
inline Mapping
directory_lookup(LDAP *ld, const Config &cfg, const std::string &base_dn, const std::string &name)
{
    need(simple_name(name), "invalid username for directory query");
    const bool key_trust = cfg.source == CertificateSource::KeyTrust;
    timeval tv{10, 0};
    const auto filter = std::format("(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))", name);
    const char *attrs[] = {"userPrincipalName", key_trust ? "objectGUID" : nullptr, nullptr};
    LdapMessage res;
    const int rc = ldap_search_ext_s(ld,
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

    // The size limit of two is deliberate: a truncated result still proves the name is ambiguous.
    if ((rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) || !res)
        fail(std::format("LDAP search failed: {}", ldap_err2string(rc)));
    const int count = ldap_count_entries(ld, res.get());
    if (count == 0) fail(std::format("user '{}' not found in Active Directory", name));
    if (count != 1) fail(std::format("ambiguous user '{}': multiple Active Directory entries found", name));
    LDAPMessage *entry = ldap_first_entry(ld, res.get());
    need(entry != nullptr, "failed to get LDAP entry");
    const LdapValues upns(ldap_get_values_len(ld, entry, "userPrincipalName"));
    need(!upns || ldap_count_values_len(upns.get()) <= 1,
         "Active Directory entry has multiple userPrincipalName values");

    // An account without an explicit userPrincipalName has the implicit one.
    const auto *upn = upns ? upns.get()[0] : nullptr;
    Mapping mapping{.name = name,
                    .upn =
                        upn && upn->bv_len ? std::string(upn->bv_val, upn->bv_len) : name + "@" + cfg.domain};
    if (key_trust)
    {
        // Address the account by its immutable GUID so moves and renames cannot redirect the write or
        // cleanup.
        const LdapValues guids(ldap_get_values_len(ld, entry, "objectGUID"));
        need(guids && ldap_count_values_len(guids.get()) == 1 && guids.get()[0]->bv_len == 16,
             "Active Directory entry has no valid objectGUID");
        mapping.object_ref = std::format("<GUID={}>", hex(byte_view({guids.get()[0]->bv_val, 16})));
    }
    return mapping;
}

// --- Key Trust (msDS-KeyCredentialLink) credential construction, per MS-ADTS 2.2.20. ---

// Marks credentials written by CRAFT so that an entry orphaned by a crash or power loss can be recognized:
// {c7a4f7b2-5d1e-4c9a-9b3f-43524146544b} in the directory's binary GUID layout.
inline constexpr std::array<unsigned char, 16> KEY_TRUST_DEVICE_ID{
    0xb2, 0xf7, 0xa4, 0xc7, 0x1e, 0x5d, 0x9a, 0x4c, 0x9b, 0x3f, 0x43, 0x52, 0x41, 0x46, 0x54, 0x4b};

inline Bytes sha256(ByteView data)
{
    Bytes digest(EVP_MAX_MD_SIZE);
    unsigned length = 0;
    sslneed(EVP_Digest(data.data(), data.size(), digest.data(), &length, EVP_sha256(), nullptr) == 1,
            "SHA-256 digest");
    digest.resize(length);
    return digest;
}

// Append a little-endian integer of the given width.
inline void le(Bytes &b, uint64_t value, int width)
{
    for (int i = 0; i < width; ++i)
        b.push_back(static_cast<unsigned char>(value >> (8 * i)));
}

// Serialize an RSA public key as a CNG BCRYPT_RSAPUBLIC_BLOB ("RSA1"), the Key Trust key material.
inline Bytes rsa_public_blob(EVP_PKEY *key)
{
    need(EVP_PKEY_base_id(key) == EVP_PKEY_RSA, "Key Trust requires an RSA key");
    BigNum modulus, exponent;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    sslneed(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, out(modulus)) == 1 &&
                EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, out(exponent)) == 1,
            "read RSA public parameters");
#else
    const BIGNUM *n = nullptr, *e = nullptr;
    if (const RSA *rsa = EVP_PKEY_get0_RSA(key)) RSA_get0_key(rsa, &n, &e, nullptr);
    modulus.reset(n ? BN_dup(n) : nullptr);
    exponent.reset(e ? BN_dup(e) : nullptr);
    sslneed(modulus && exponent, "read RSA public parameters");
#endif
    const int mod_len = BN_num_bytes(modulus.get()), exp_len = BN_num_bytes(exponent.get());
    sslneed(mod_len > 0 && exp_len > 0, "RSA parameter length");
    Bytes blob{'R', 'S', 'A', '1'};
    le(blob, static_cast<uint32_t>(BN_num_bits(modulus.get())), 4);
    le(blob, static_cast<uint32_t>(exp_len), 4);
    le(blob, static_cast<uint32_t>(mod_len), 4);
    le(blob, 0, 8); // cbPrime1 and cbPrime2
    const size_t header = blob.size();
    blob.resize(header + static_cast<size_t>(exp_len) + static_cast<size_t>(mod_len));
    sslneed(BN_bn2bin(exponent.get(), blob.data() + header) == exp_len &&
                BN_bn2bin(modulus.get(), blob.data() + header + exp_len) == mod_len,
            "encode RSA public blob");
    return blob;
}

// Build a version 2 Key Credential Link blob advertising a single NGC (Key Trust) key.
inline Bytes key_credential_blob(EVP_PKEY *key, ByteView device_id, time_t now)
{
    need(device_id.size() == 16, "device identifier must be a 16-byte GUID");
    const auto entry = [](Bytes &b, unsigned char identifier, ByteView value)
    {
        need(value.size() <= 0xffff, "key credential entry too large");
        le(b, value.size(), 2);
        b.push_back(identifier);
        b.insert(b.end(), value.begin(), value.end());
    };
    const Bytes material = rsa_public_blob(key);
    Bytes stamp; // Windows FILETIME
    le(stamp, (static_cast<uint64_t>(now) + 11644473600ULL) * 10000000ULL, 8);

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
    le(blob, 0x00000200, 4);             // Version 2
    entry(blob, 0x01, sha256(material)); // KeyID = SHA-256(KeyMaterial)
    entry(blob, 0x02, sha256(tail));     // KeyHash = SHA-256(subsequent entries)
    return join(std::move(blob), tail);
}

// Represent the blob as the DN-Binary value stored in msDS-KeyCredentialLink.
inline std::string dn_binary(ByteView blob, const std::string &dn)
{
    need(!dn.empty() && dn.find_first_of("\r\n") == std::string::npos, "invalid key credential object DN");
    return std::format("B:{}:{}:{}", 2 * blob.size(), hex(blob, true), dn);
}

struct KeyTrustPair
{
    Cert leaf;
    Cert ca;
};

// Start an unsigned version 3 certificate with a random serial, backdated five minutes for clock skew.
inline Cert new_certificate(X509_NAME *subject, X509_NAME *issuer, EVP_PKEY *key, long seconds)
{
    Cert c(X509_new());
    Bytes serial = random_bytes(16);
    serial[0] &= 0x7f;
    const BigNum number(BN_bin2bn(serial.data(), static_cast<int>(serial.size()), nullptr));
    sslneed(c && number && X509_set_version(c.get(), 2) == 1 &&
                BN_to_ASN1_INTEGER(number.get(), X509_get_serialNumber(c.get())) != nullptr &&
                X509_gmtime_adj(X509_getm_notBefore(c.get()), -300) != nullptr &&
                X509_gmtime_adj(X509_getm_notAfter(c.get()), seconds) != nullptr &&
                X509_set_subject_name(c.get(), subject) == 1 && X509_set_issuer_name(c.get(), issuer) == 1 &&
                X509_set_pubkey(c.get(), key) == 1,
            "certificate initialize");
    return c;
}

// Build a short-lived PKINIT leaf under an ephemeral local CA: MIT Kerberos sends the leaf in its CMS
// SignedData only when it chains to an anchor. The CA key is discarded as soon as the leaf is signed.
inline KeyTrustPair
make_key_trust_pair(EVP_PKEY *key, std::string_view cn, std::string_view upn, uint32_t validity)
{
    const Key ca_key = generate_key(2048);
    const Name ca_name = common_name_only("CRAFT Key Trust CA"), name = common_name_only(cn);
    const auto extend = [](X509 *c, std::initializer_list<Ext> extensions)
    {
        for (const auto &e : extensions)
            sslneed(X509_add_ext(c, e.get(), -1) == 1, "certificate extension");
    };
    Cert ca = new_certificate(ca_name.get(), ca_name.get(), ca_key.get(), static_cast<long>(validity) + 3600);
    extend(ca.get(),
           {conf_extension(NID_basic_constraints, "critical,CA:TRUE"),
            conf_extension(NID_key_usage, "critical,keyCertSign,cRLSign")});
    Cert leaf = new_certificate(name.get(), ca_name.get(), key, static_cast<long>(validity));
    extend(leaf.get(),
           {upn_extension(upn),
            conf_extension(NID_basic_constraints, "critical,CA:FALSE"),
            conf_extension(NID_key_usage, "critical,digitalSignature"),
            logon_eku_extension()});
    sslneed(X509_sign(ca.get(), ca_key.get(), EVP_sha256()) > 0 &&
                X509_sign(leaf.get(), ca_key.get(), EVP_sha256()) > 0,
            "sign Key Trust certificates");
    return {std::move(leaf), std::move(ca)};
}

// Add or remove exactly one Key Trust value, leaving any other key credentials on the object untouched.
inline void modify_key_credential(
    LDAP *ld, const std::string &dn, const std::string &value, bool add, bool *cleanup_required = nullptr)
{
    std::string editable = value;
    char *values[] = {editable.data(), nullptr};
    LDAPMod mod{};
    mod.mod_op = add ? LDAP_MOD_ADD : LDAP_MOD_DELETE;
    mod.mod_type = const_cast<char *>("msDS-KeyCredentialLink");
    mod.mod_values = values;
    LDAPMod *mods[] = {&mod, nullptr};

    // Only a server rejection conclusively rules out publication; local errors leave the write uncertain.
    if (cleanup_required) *cleanup_required = true;
    const int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    if (cleanup_required && rc != LDAP_SUCCESS && !LDAP_API_ERROR(rc)) *cleanup_required = false;
    if (rc == LDAP_SUCCESS || (!add && rc == LDAP_NO_SUCH_ATTRIBUTE)) return;
    fail(std::format("{} msDS-KeyCredentialLink failed: {}", add ? "add" : "remove", ldap_err2string(rc)));
}

// Retry cleanup with a fresh connection and report a residual credential if the directory stays unavailable.
inline bool
detach_key_credential(const Config &cfg, LDAP *ld, const std::string &dn, const std::string &value) noexcept
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
        audit(LOG_CRIT,
              std::format("CRITICAL: could not remove temporary msDS-KeyCredentialLink from {}; remove it "
                          "manually ({})",
                          dn,
                          error.what()));
        dprintf(STDERR_FILENO,
                "craft-worker: CRITICAL: failed to remove the temporary key credential from %s; remove it "
                "manually\n",
                sanitize_ascii(dn).c_str());
    }
    return false;
}

// Publish the credential from an independent guardian process that also owns its removal, so the key is
// withdrawn however the worker ends and even when the outcome of the LDAP write is uncertain. Closing the
// returned descriptor triggers removal.
inline Fd start_key_credential_cleanup(
    const Config &cfg, const std::string &object_ref, const std::string &value, pid_t &child, int lock_fd)
{
    Pipe control = make_pipe(), ready = make_pipe();
    child = fork_child(
        [&]
        {
            // Leave the caller's session and block every signal: the worker's alarm, its death, and the
            // terminal's interrupt, quit, suspend and hangup must not stop cleanup or release the issuance
            // lock.
            sigset_t all;
            sigfillset(&all);
            alarm(0);
            sysneed(setsid() >= 0 && prctl(PR_SET_PDEATHSIG, 0) == 0 &&
                        sigprocmask(SIG_BLOCK, &all, nullptr) == 0,
                    "isolate key cleanup process");
            {
                const Fd null(open("/dev/null", O_RDWR));
                sysneed(null.get() >= 0 && dup2(null.get(), STDIN_FILENO) == STDIN_FILENO &&
                            dup2(null.get(), STDOUT_FILENO) == STDOUT_FILENO,
                        "key cleanup standard descriptors");
            }
            constexpr int trigger = 3, armed = 4; // the issuance lock, when held, stays open as 5
            keep_only({control.reader.get(), ready.writer.get(), lock_fd});
            try
            {
                // Bind a separate connection; an LDAP socket inherited across fork must never be shared.
                const auto ld = ldap_connect(cfg.kt_dc_url);
                bool cleanup_required = false, removed = false;
                {
                    ScopeExit cleanup(
                        [&]() noexcept
                        {
                            if (cleanup_required)
                                removed = detach_key_credential(cfg, ld.get(), object_ref, value);
                        });
                    modify_key_credential(ld.get(), object_ref, value, true, &cleanup_required);
                    const unsigned char published = 1;
                    write_all(armed, {&published, 1});
                    ::close(armed);
                    unsigned char ignored;
                    ssize_t count;
                    do
                        count = read(trigger, &ignored, 1);
                    while (count < 0 && errno == EINTR);
                }
                return removed ? 0 : 1;
            }
            catch (const std::exception &error)
            {
                audit(
                    LOG_WARNING,
                    std::format("key trust directory operation failed for {}: {}", object_ref, error.what()));
                throw;
            }
        },
        "craft-worker");
    control.reader = Fd();
    ready.writer = Fd();
    need(read_all(ready.reader.get(), 1) == Bytes{1},
         "key trust publication failed; existing cache was not replaced");
    return std::move(control.writer);
}

// Release credentials only after the guardian confirms successful removal.
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
