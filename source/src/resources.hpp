#pragma once
#include "common.hpp"
#include <memory>
#include <krb5.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

namespace craft
{
// Own C allocations immediately; raw pointers elsewhere are borrowed library views.
template <class T, auto Free>
    requires std::invocable<decltype(Free), T *>
struct Deleter
{
    void operator()(T *value) const noexcept
    {
        // Free managed C pointer if non-null.
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
        // Verify target pointer is uninitialized.
        need(!owner_, "C output would overwrite an owned resource");
    }

    ~Out() noexcept
    {
        // Adopt out-parameter value into managed owner.
        owner_.reset(value_);
    }

    Out(const Out &) = delete;

    Out &operator=(const Out &) = delete;

    operator typename Owner::pointer *() noexcept
    {
        // Expose address of internal raw pointer.
        return &value_;
    }
};

template <class Owner> [[nodiscard]] auto out(Owner &owner)
{
    // Create RAII out-adapter for C API output parameter.
    return Out<Owner>(owner);
}

// Free OpenSSL stacks and their elements as one owned resource.
inline void free_extensions(STACK_OF(X509_EXTENSION) * p) noexcept
{
    // Free OpenSSL extension stack and elements.
    sk_X509_EXTENSION_pop_free(p, X509_EXTENSION_free);
}

inline void free_certificates(STACK_OF(X509) * p) noexcept
{
    // Free OpenSSL certificate stack and elements.
    sk_X509_pop_free(p, X509_free);
}

inline void free_asn1_sequence(STACK_OF(ASN1_TYPE) * p) noexcept
{
    // Free ASN1 sequence stack and elements.
    sk_ASN1_TYPE_pop_free(p, ASN1_TYPE_free);
}

using Extensions = Owned<STACK_OF(X509_EXTENSION), free_extensions>;
using Certificates = Owned<STACK_OF(X509), free_certificates>;
using Asn1Sequence = Owned<STACK_OF(ASN1_TYPE), free_asn1_sequence>;

// Carry the owning Kerberos context in each deleter; destroy handles before the context.
template <class T, auto Free> struct KrbDeleter
{
    krb5_context context = nullptr;

    void operator()(T *value) const noexcept
    {
        // Free Kerberos handle within associated context.
        if (value) (void)Free(context, value);
    }
};

template <class T, auto Free> using KrbOwned = std::unique_ptr<T, KrbDeleter<T, Free>>;

template <class T, auto Free> [[nodiscard]] auto krb_owner(krb5_context context, T *value = nullptr)
{
    // Construct context-bound Kerberos RAII owner.
    return KrbOwned<T, Free>(value, {context});
}

using KrbContext = Owned<std::remove_pointer_t<krb5_context>, krb5_free_context>;
using KrbCache = KrbOwned<std::remove_pointer_t<krb5_ccache>, krb5_cc_destroy>;

} // namespace craft
