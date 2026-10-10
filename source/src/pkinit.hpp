#pragma once

// Kerberos exchanges: the transport account's in-memory credentials and the caller's PKINIT TGT.
#include "x509.hpp"
#include <sys/mman.h>
#include <iostream>

namespace craft
{
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
        krb_check(ctx(), code, "initialize MIT Kerberos");
        transport_ = KrbCache(nullptr, {ctx()});
    }

    [[nodiscard]] krb5_context ctx() const noexcept
    {
        return context_.get();
    }

    // Authenticate the directory/CES transport account from its keytab into a private memory cache.
    void acquire_transport(const Config &c)
    {
        const auto keytab = path("submitter.keytab");
        root_open(keytab, Trusted::Secret);
        const auto p = parse_principal(ctx(), c.service_principal);
        auto kt = krb_owner<std::remove_pointer_t<krb5_keytab>, krb5_kt_close>(ctx());
        auto o = krb_owner<krb5_get_init_creds_opt, krb5_get_init_creds_opt_free>(ctx());
        krb5_creds cred{};
        ScopeExit free_cred([&]() noexcept { krb5_free_cred_contents(ctx(), &cred); });
        krb_check(
            ctx(), krb5_kt_resolve(ctx(), ("FILE:" + keytab).c_str(), out(kt)), "open transport keytab");
        krb_check(ctx(), krb5_get_init_creds_opt_alloc(ctx(), out(o)), "transport options");
        auto types = AES_TYPES;
        krb5_get_init_creds_opt_set_etype_list(o.get(), types.data(), static_cast<int>(types.size()));
        krb5_get_init_creds_opt_set_tkt_life(o.get(), 300);
        krb5_get_init_creds_opt_set_renew_life(o.get(), 0);

        // Only the isolated transport account requests forwardability, for CES constrained delegation.
        krb5_get_init_creds_opt_set_forwardable(o.get(), c.ces_auth == "negotiate");
        krb5_get_init_creds_opt_set_proxiable(o.get(), 0);
        krb_check(ctx(),
                  krb5_get_init_creds_keytab(ctx(), &cred, p.get(), kt.get(), 0, nullptr, o.get()),
                  "authenticate directory/CES transport account");
        require_aes_key(cred.keyblock);
        (void)ticket_enctype(ctx(), cred.ticket);
        krb_check(
            ctx(), krb5_cc_new_unique(ctx(), "MEMORY", nullptr, out(transport_)), "transport memory cache");
        krb_check(ctx(), krb5_cc_initialize(ctx(), transport_.get(), p.get()), "initialize transport cache");
        krb_check(ctx(), krb5_cc_store_cred(ctx(), transport_.get(), &cred), "store transport credentials");
        auto full = krb_owner<char, krb5_free_string>(ctx());
        krb_check(ctx(), krb5_cc_get_full_name(ctx(), transport_.get(), out(full)), "transport cache name");
        sysneed(setenv("KRB5CCNAME", full.get(), 1) == 0, "set private transport cache");
    }
};

// Pass temporary PKINIT material to MIT Kerberos through sealed, private memory files.
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

// Serialize PEM straight into a memory file and erase OpenSSL's buffer, so no other copy of a private key
// remains.
template <std::invocable<BIO *> Write> inline Fd pem_file(const char *name, Write write)
{
    const Bio bio(BIO_new(BIO_s_mem()));
    sslneed(bio != nullptr, "PEM buffer allocate");
    ScopeExit erase(
        [&]() noexcept
        {
            char *data = nullptr;
            const auto length = BIO_get_mem_data(bio.get(), &data);
            if (length > 0) OPENSSL_cleanse(data, static_cast<size_t>(length));
        });
    sslneed(write(bio.get()) == 1, "serialize temporary PKINIT identity");
    return memory_file(name, bioview(bio.get()));
}

inline krb5_error_code refuse_prompt(krb5_context, void *, const char *, const char *, int, krb5_prompt[])
{
    return KRB5_LIBOS_CANTREADPWD;
}

// Report a KDC grant shorter than requested: fatal in strict mode, otherwise a warning.
inline void short_grant(const Config &cfg, const std::string &message)
{
    if (cfg.require_full_tgt_lifetime) fail(message);
    std::cerr << "craft-worker: WARNING: " << message << '\n';
}

// Validate the issued ticket; never rewrite its expiry or confuse renewal with validity.
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
    const int64_t start = start_time(creds.times), end = creds.times.endtime, till = creds.times.renew_till;
    if (cfg.renew > 0)
    {
        need((creds.ticket_flags & TKT_FLG_RENEWABLE) != 0,
             "KDC did not return a renewable credential as configured");
        need(till > end, "KDC returned a renewable credential with renew_till not exceeding endtime");
        need(till - start <= int64_t{cfg.renew} + 5 && till <= int64_t{now} + cfg.renew + 5,
             "KDC returned an excessive renewable lifetime; synchronize clocks");
        if (till - start + 5 < cfg.renew)
            short_grant(
                cfg,
                std::format("KDC granted {} seconds renewable lifetime; requested {}. Review DC ticket "
                            "renewal policy.",
                            till - start,
                            cfg.renew));
    }
    else
        need(!(creds.ticket_flags & TKT_FLG_RENEWABLE) && till == 0,
             "KDC returned a renewable credential when renewal was not requested");
    require_aes_key(creds.keyblock);
    need(start >= int64_t{requested_at} - 300 && start <= int64_t{now} + 300 && end > now && end > start &&
             end - start <= int64_t{cfg.tgt} + 5 && end <= int64_t{now} + cfg.tgt + 5,
         "KDC returned an excessive/invalid TGT lifetime; synchronize clocks");
    if (end - start + 5 < cfg.tgt)
        short_grant(cfg,
                    std::format("KDC granted {} seconds; requested {}. Review DC ticket policy and PKINIT "
                                "certificate/key-lifetime limits; a renewal window is not ticket validity.",
                                end - start,
                                cfg.tgt));
}

// Request the configured TGT with PKINIT only; the DC alone decides what lifetime it can issue. A Key Trust
// leaf arrives with its ephemeral issuer, which must be an anchor for MIT to send the leaf at all.
inline Bytes
get_tgt(Kerberos &k, const Config &cfg, const Mapping &m, X509 *cert, EVP_PKEY *key, X509 *ca = nullptr)
{
    const auto ctx = k.ctx();
    const Fd certfd = pem_file("craft-cert", [&](BIO *b) { return PEM_write_bio_X509(b, cert); });
    const Fd keyfd = pem_file(
        "craft-key",
        [&](BIO *b) { return PEM_write_bio_PrivateKey(b, key, nullptr, nullptr, 0, nullptr, nullptr); });
    Fd anchorfd;
    auto anchors = "FILE:" + path("kdc-trust.pem");
    if (ca)
    {
        const Bio issuer(BIO_new(BIO_s_mem()));
        sslneed(issuer && PEM_write_bio_X509(issuer.get(), ca) == 1, "serialize CA anchor");
        const Bytes configured = read_all(root_open(path("kdc-trust.pem")).get());
        anchorfd = memory_file("craft-anchors", join(configured, bioview(issuer.get())));
        anchors = std::format("FILE:/proc/self/fd/{}", anchorfd.get());
    }
    const auto identity = std::format("FILE:/proc/self/fd/{},/proc/self/fd/{}", certfd.get(), keyfd.get());
    const auto principal = parse_principal(ctx, m.name + "@" + cfg.realm),
               tgs = tgs_principal(ctx, cfg.realm);
    auto opts = krb_owner<krb5_get_init_creds_opt, krb5_get_init_creds_opt_free>(ctx);
    krb5_creds creds{};
    ScopeExit free_creds([&]() noexcept { krb5_free_cred_contents(ctx, &creds); });
    krb_check(ctx, krb5_get_init_creds_opt_alloc(ctx, out(opts)), "PKINIT options");
    auto types = AES_TYPES;
    krb5_preauthtype pa = KRB5_PADATA_PK_AS_REQ;
    krb5_get_init_creds_opt_set_etype_list(opts.get(), types.data(), static_cast<int>(types.size()));
    krb5_get_init_creds_opt_set_tkt_life(opts.get(), static_cast<krb5_deltat>(cfg.tgt));
    krb5_get_init_creds_opt_set_renew_life(opts.get(), static_cast<krb5_deltat>(cfg.renew));
    krb5_get_init_creds_opt_set_forwardable(opts.get(), 0);
    krb5_get_init_creds_opt_set_proxiable(opts.get(), 0);
    krb5_get_init_creds_opt_set_canonicalize(opts.get(), 0);
    krb5_get_init_creds_opt_set_change_password_prompt(opts.get(), 0);
    krb5_get_init_creds_opt_set_preauth_list(opts.get(), &pa, 1);
    krb_check(ctx,
              krb5_get_init_creds_opt_set_pa(ctx, opts.get(), "X509_user_identity", identity.c_str()),
              "set PKINIT certificate and key");
    krb_check(ctx,
              krb5_get_init_creds_opt_set_pa(ctx, opts.get(), "X509_anchors", anchors.c_str()),
              "set KDC trust anchors");

    // A null password and a prompter that refuses: users have no password or keytab fallback.
    const time_t requested_at = time(nullptr);
    krb_check(ctx,
              krb5_get_init_creds_password(
                  ctx, &creds, principal.get(), nullptr, refuse_prompt, nullptr, 0, nullptr, opts.get()),
              "user PKINIT");
    validate_tgt(ctx, cfg, creds, principal.get(), tgs.get(), requested_at, time(nullptr));
    const auto outer = ticket_enctype(ctx, creds.ticket);
    std::cerr << std::format(
        "craft-worker: TGT expires at Unix {}{}; session enctype={}; ticket enctype={}\n",
        creds.times.endtime,
        creds.times.renew_till > 0 ? std::format(" (renewable until Unix {})", creds.times.renew_till) : "",
        creds.keyblock.enctype,
        outer);
    return file_cache(ctx, creds);
}

} // namespace craft
