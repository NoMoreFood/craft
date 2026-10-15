#pragma once

// Protocol transition and constrained delegation keep the broker's authority inside this worker.
#include "pkinit.hpp"
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi_ext.h>

namespace craft
{
inline void gss_check(krb5_context ctx, OM_uint32 major, OM_uint32 minor, std::string_view operation)
{
    if (!GSS_ERROR(major)) return;
    krb_check(ctx, static_cast<krb5_error_code>(minor), operation);
    fail(operation);
}

inline Bytes delegate_services(krb5_context ctx,
                               const Config &cfg,
                               krb5_principal client,
                               krb5_principal broker,
                               krb5_ccache transport,
                               const krb5_creds &evidence)
{
    // Request every configured target before releasing any bytes; one denied target fails the whole batch.
    Bytes result;
    ScopeExit erase([&]() noexcept { wipe(result); });
    const auto requested_at = time(nullptr);
    for (const auto &spn : cfg.service_spns)
    {
        const auto target = parse_principal(ctx, spn);
        krb5_creds request{};
        request.client = broker;
        request.server = target.get();
        request.second_ticket = evidence.ticket;
        request.times.endtime = static_cast<krb5_timestamp>(requested_at + cfg.service_ticket_seconds);
        auto ticket = krb_owner<krb5_creds, krb5_free_creds>(ctx);
        krb_check(ctx,
                  krb5_get_credentials(ctx,
                                       KRB5_GC_CONSTRAINED_DELEGATION | KRB5_GC_CANONICALIZE | KRB5_GC_NO_STORE,
                                       transport, &request, out(ticket)),
                  "S4U2Proxy target " + spn);

        // MIT may attach the evidence as second_ticket; export only the final service ticket and its key.
        krb5_free_data_contents(ctx, &ticket->second_ticket);
        ticket->second_ticket = {};
        const auto now = time(nullptr);
        validate_service_credential(ctx, *ticket, client, target.get(), now);
        need(start_time(ticket->times) >= int64_t{requested_at} - 300 && ticket->times.endtime > now &&
                 ticket->times.endtime <= int64_t{requested_at} + cfg.service_ticket_seconds + 5 &&
                 ticket->times.endtime - start_time(ticket->times) <= cfg.service_ticket_seconds + 5,
             "KDC returned an excessive or expired service ticket lifetime");
        if (result.empty()) result = file_cache(ctx, *ticket);
        else append_cache_credential(ctx, result, *ticket);
    }
    need(!result.empty(), "no delegated service tickets");
    erase.release();
    return result;
}

inline Bytes get_service_tickets(Kerberos &krb, const Config &cfg, const Mapping &mapping)
{
    const auto ctx = krb.ctx();
    const auto username = mapping.name + "@" + cfg.realm;
    const auto client = parse_principal(ctx, username), broker = parse_principal(ctx, cfg.service_principal);
    const auto realm = krb5_princ_realm(ctx, broker.get());
    need(!krb5_principal_compare(ctx, client.get(), broker.get()) &&
             std::string_view(realm->data, realm->length) == cfg.realm,
         "broker must be a separate account in the configured realm");
    krb.acquire_transport(cfg);

    // Ask only the Kerberos mechanism for an S4U2Self evidence ticket for the fixed Linux identity.
    OM_uint32 minor = 0;
    gss_cred_id_t broker_cred = GSS_C_NO_CREDENTIAL, proxy = GSS_C_NO_CREDENTIAL;
    gss_name_t name = GSS_C_NO_NAME;
    ScopeExit release(
        [&]() noexcept
        {
            gss_release_name(&minor, &name);
            gss_release_cred(&minor, &proxy);
            gss_release_cred(&minor, &broker_cred);
        });
    auto major = gss_krb5_import_cred(&minor, krb.transport(), nullptr, nullptr, &broker_cred);
    gss_check(ctx, major, minor, "import broker credentials");
    gss_buffer_desc buffer{username.size(), const_cast<char *>(username.data())};
    major = gss_import_name(&minor, &buffer, GSS_KRB5_NT_PRINCIPAL_NAME, &name);
    gss_check(ctx, major, minor, "import caller principal");
    major = gss_acquire_cred_impersonate_name(&minor, broker_cred, name, cfg.service_ticket_seconds,
                                             GSS_C_NO_OID_SET, GSS_C_INITIATE, &proxy, nullptr, nullptr);
    gss_check(ctx, major, minor, "S4U2Self protocol transition");

    // The copied proxy cache is private: it contains the broker TGT and must never be published.
    KrbCache evidence_cache(nullptr, {ctx});
    krb_check(ctx, krb5_cc_new_unique(ctx, "MEMORY", nullptr, out(evidence_cache)), "private evidence cache");
    krb_check(ctx, krb5_cc_initialize(ctx, evidence_cache.get(), client.get()), "initialize evidence cache");
    major = gss_krb5_copy_ccache(&minor, proxy, evidence_cache.get());
    gss_check(ctx, major, minor, "copy private evidence credentials");
    krb5_creds match{}, evidence{};
    ScopeExit free_evidence([&]() noexcept { krb5_free_cred_contents(ctx, &evidence); });
    match.client = client.get();
    match.server = broker.get();
    krb_check(ctx, krb5_cc_retrieve_cred(ctx, evidence_cache.get(), 0, &match, &evidence),
              "read S4U2Self evidence ticket");
    need((evidence.ticket_flags & TKT_FLG_FORWARDABLE) != 0,
         "S4U2Self requires protocol transition on the broker and a delegable user");

    return delegate_services(ctx, cfg, client.get(), broker.get(), krb.transport(), evidence);
}

} // namespace craft
