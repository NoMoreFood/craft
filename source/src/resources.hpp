#pragma once

// Ownership of C library resources, plus the Kerberos handles, ticket checks and cache encoding shared by the
// worker and the maintainer.
#include "common.hpp"
#include <memory>
#include <krb5.h>

namespace craft
{
// Own C allocations immediately; raw pointers elsewhere are borrowed library views.
template <class T, auto Free>
    requires std::invocable<decltype(Free), T *>
struct Deleter
{
    void operator()(T *value) const noexcept
    {
        if (value) (void)Free(value);
    }
};

template <class T, auto Free> using Owned = std::unique_ptr<T, Deleter<T, Free>>;

// Adopt C output parameters even on failure; C++20 has no std::out_ptr.
template <class Owner> class Out
{
    Owner &owner_;
    typename Owner::pointer value_ = nullptr;

public:
    explicit Out(Owner &owner) : owner_(owner)
    {
        need(!owner_, "C output would overwrite an owned resource");
    }

    ~Out() noexcept
    {
        owner_.reset(value_);
    }

    Out(const Out &) = delete;

    Out &operator=(const Out &) = delete;

    operator typename Owner::pointer *() noexcept
    {
        return &value_;
    }
};

template <class Owner> [[nodiscard]] auto out(Owner &owner)
{
    return Out<Owner>(owner);
}

// Carry the owning Kerberos context in each deleter; destroy handles before the context.
template <class T, auto Free> struct KrbDeleter
{
    krb5_context context = nullptr;

    void operator()(T *value) const noexcept
    {
        if (value) (void)Free(context, value);
    }
};

template <class T, auto Free> using KrbOwned = std::unique_ptr<T, KrbDeleter<T, Free>>;

template <class T, auto Free> [[nodiscard]] auto krb_owner(krb5_context context, T *value = nullptr)
{
    return KrbOwned<T, Free>(value, {context});
}

inline void krb_check(krb5_context ctx, krb5_error_code code, std::string_view operation)
{
    if (!code) return;
    if (!ctx) fail(operation);
    auto message = krb_owner<const char, krb5_free_error_message>(ctx, krb5_get_error_message(ctx, code));
    fail(std::format("{}: {}", operation, message ? message.get() : "Kerberos error"));
}

using KrbContext = Owned<std::remove_pointer_t<krb5_context>, krb5_free_context>;
using KrbCache = KrbOwned<std::remove_pointer_t<krb5_ccache>, krb5_cc_destroy>;
using KrbPrincipal = KrbOwned<std::remove_pointer_t<krb5_principal>, krb5_free_principal>;

inline KrbPrincipal parse_principal(krb5_context ctx, const std::string &name)
{
    KrbPrincipal principal(nullptr, {ctx});
    krb_check(ctx, krb5_parse_name(ctx, name.c_str(), out(principal)), "parse Kerberos principal");
    return principal;
}

inline KrbPrincipal tgs_principal(krb5_context ctx, std::string_view realm)
{
    return parse_principal(ctx, std::format("krbtgt/{0}@{0}", realm));
}

// Restrict both transport and user initial credentials to interoperable AES enctypes.
inline constexpr std::array AES_TYPES{ENCTYPE_AES256_CTS_HMAC_SHA1_96, ENCTYPE_AES128_CTS_HMAC_SHA1_96};

// Enforce prohibited ticket flags across issuance and maintenance.
inline constexpr auto PROHIBITED_TKT_FLAGS = TKT_FLG_FORWARDABLE | TKT_FLG_FORWARDED | TKT_FLG_PROXIABLE |
                                             TKT_FLG_PROXY | TKT_FLG_MAY_POSTDATE | TKT_FLG_POSTDATED |
                                             TKT_FLG_INVALID;

inline constexpr bool is_aes(krb5_enctype type) noexcept
{
    return std::ranges::find(AES_TYPES, type) != AES_TYPES.end();
}

inline void require_aes_key(const krb5_keyblock &key)
{
    need(is_aes(key.enctype) && key.contents &&
             key.length == (key.enctype == ENCTYPE_AES256_CTS_HMAC_SHA1_96 ? 32U : 16U),
         "KDC session key is not a valid AES128/AES256 key");
}

inline krb5_enctype ticket_enctype(krb5_context ctx, const krb5_data &encoded)
{
    auto ticket = krb_owner<krb5_ticket, krb5_free_ticket>(ctx);
    const auto code = krb5_decode_ticket(&encoded, out(ticket));
    need(code == 0 && ticket, "decode returned TGT envelope");
    need(is_aes(ticket->enc_part.enctype),
         "KDC encrypted the TGT with a non-AES key; review krbtgt keys/policy");
    return ticket->enc_part.enctype;
}

// A ticket without an explicit start time is valid from its authentication time.
inline int64_t start_time(const krb5_ticket_times &times) noexcept
{
    return times.starttime ? times.starttime : times.authtime;
}

inline void u32(Bytes &b, uint32_t n)
{
    for (int shift = 24; shift >= 0; shift -= 8)
        b.push_back(static_cast<unsigned char>(n >> shift));
}

inline void counted(Bytes &b, const krb5_data &d)
{
    u32(b, d.length);
    b.insert(b.end(), d.data, d.data + d.length);
}

inline void append_cache_credential(krb5_context ctx, Bytes &b, krb5_creds &cred)
{
    krb5_data *marshaled = nullptr;
    ScopeExit free_marshaled(
        [&]() noexcept
        {
            if (!marshaled) return;
            if (marshaled->data) ::explicit_bzero(marshaled->data, marshaled->length);
            krb5_free_data(ctx, marshaled);
        });
    need(krb5_marshal_credentials(ctx, &cred, &marshaled) == 0, "serialize TGT failed");
    need(b.size() + marshaled->length <= MAX_BLOB, "TGT cache exceeds size limit");
    b.insert(b.end(), marshaled->data, marshaled->data + marshaled->length);
}

// Write the version 4 FILE header and default principal; MIT serializes each credential record.
inline Bytes file_cache(krb5_context ctx, krb5_creds &cred)
{
    Bytes b{5, 4, 0, 0};
    krb5_principal p = cred.client;
    u32(b, static_cast<uint32_t>(krb5_princ_type(ctx, p)));
    u32(b, static_cast<uint32_t>(krb5_princ_size(ctx, p)));
    counted(b, *krb5_princ_realm(ctx, p));
    for (int i = 0; i < krb5_princ_size(ctx, p); ++i)
        counted(b, *krb5_princ_component(ctx, p, i));
    append_cache_credential(ctx, b, cred);
    return b;
}

} // namespace craft
