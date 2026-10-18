// Exercise delegation requests and real MIT cache parsing; only the KDC exchange is substituted.
#include "../src/delegation.hpp"
#include "../src/maintain.hpp"
#include "harness.hpp"
using namespace craft;
using testing::test;
using testing::rejects;

static krb5_principal expected_client, expected_broker;
static unsigned requests = 0;
static std::string scenario;
static time_t time_offset = 0;

// Advance the acquisition clock to model a slow batch without delaying the test process.
extern "C" time_t __real_time(time_t *);
extern "C" time_t __wrap_time(time_t *output)
{
    const auto now = __real_time(nullptr) + time_offset;
    if (output) *output = now;
    return now;
}

static Bytes envelope(krb5_principal server, krb5_enctype enctype)
{
    const auto text = [](const krb5_data &value)
    {
        return der(0x1b, byte_view(std::string_view(value.data, value.length)));
    };
    Bytes names;
    for (int i = 0; i < server->length; ++i)
    {
        const auto part = text(server->data[i]);
        names.insert(names.end(), part.begin(), part.end());
    }
    const auto principal = der(0xa2, der(0x30, join(der(0xa0, der(0x02, Bytes{2})),
                                                    der(0xa1, der(0x30, names)))));
    const auto encrypted = der(0xa3, der(0x30, join(
        der(0xa0, der(0x02, Bytes{static_cast<unsigned char>(enctype)})),
        der(0xa2, der(0x04, byte_view("SYNTHETIC SERVICE TICKET"))))));
    return der(0x61, der(0x30, join(join(der(0xa0, der(0x02, Bytes{5})),
                                          der(0xa1, text(server->realm))), join(principal, encrypted))));
}

extern "C" krb5_error_code __wrap_krb5_get_credentials(
    krb5_context ctx, krb5_flags flags, krb5_ccache, krb5_creds *request, krb5_creds **output)
{
    ++requests;
    if (flags != (KRB5_GC_CONSTRAINED_DELEGATION | KRB5_GC_CANONICALIZE | KRB5_GC_NO_STORE) ||
        !krb5_principal_compare(ctx, request->client, expected_broker) ||
        std::string_view(request->second_ticket.data, request->second_ticket.length) != "PRIVATE EVIDENCE")
        return KRB5KDC_ERR_BADOPTION;
    if (scenario == "denied" && requests == 2) return KRB5KDC_ERR_BADOPTION;
    if (scenario == "expired batch" && requests == 2) time_offset = 60;

    // Include the library's evidence attachment so the test proves it is removed from exported credentials.
    const auto now = static_cast<krb5_timestamp>(time(nullptr));
    std::array<unsigned char, 32> key{};
    krb5_creds grant{};
    const auto tgt = tgs_principal(ctx, "DOMAIN.LOCAL");
    grant.client = scenario == "broker" ? expected_broker : expected_client;
    grant.server = scenario == "tgt" ? tgt.get() : request->server;
    grant.keyblock = {.magic = 0, .enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                     .length = static_cast<unsigned>(key.size()), .contents = key.data()};
    grant.times = {.authtime = now, .starttime = now, .endtime = now + 600, .renew_till = 0};
    grant.ticket_flags = TKT_FLG_FORWARDABLE | TKT_FLG_FORWARDED | TKT_FLG_PRE_AUTH;
    if (scenario == "excess") grant.times.endtime = request->times.endtime + 60;
    if (scenario == "expired batch") grant.times.endtime = now + 60;
    if (scenario == "expiry")
    {
        grant.times.authtime = grant.times.starttime = now - 110;
        grant.times.endtime = now + (requests == 1 ? 490 : 10);
        grant.ticket_flags |= TKT_FLG_RENEWABLE;
        grant.times.renew_till = now + 600;
    }
    auto encoded = envelope(scenario == "envelope" ? tgt.get() : grant.server,
                            scenario == "rc4" ? ENCTYPE_ARCFOUR_HMAC : grant.keyblock.enctype);
    grant.ticket = {.magic = 0, .length = static_cast<unsigned>(encoded.size()),
                   .data = reinterpret_cast<char *>(encoded.data())};
    grant.second_ticket = request->second_ticket;
    return krb5_copy_creds(ctx, &grant, output);
}

int main()
{
    const std::string base = "enabled=yes\ndomain=domain.local\nrealm=DOMAIN.LOCAL\n"
                             "modes=constrained_delegation\nservice_principal=broker@DOMAIN.LOCAL\n";
    const auto cfg = parse_config(base + "service_spns=cifs/files.domain.local@DOMAIN.LOCAL "
                                        "HTTP/web.domain.local@DOMAIN.LOCAL\n");
    test("service-only policy rejects home mode and invalid target policy",
         [&]
         {
             rejects([&] { parse_config(base + "service_spns=cifs/files.domain.local@DOMAIN.LOCAL\n",
                                        CertificateSource::Home); });
             for (auto spns : {"krbtgt/DOMAIN.LOCAL@DOMAIN.LOCAL", "KrBtGt/DOMAIN.LOCAL@DOMAIN.LOCAL",
                               "cifs/files.domain.local@OTHER.REALM", "cifs/*@DOMAIN.LOCAL",
                               "cifs/files.domain.local", "broker@DOMAIN.LOCAL",
                               "cifs/a@DOMAIN.LOCAL cifs/a@DOMAIN.LOCAL"})
                 rejects([&] { parse_config(base + "service_spns=" + spns + "\n"); });
             rejects([&] { parse_config(base); });
         });

    KrbContext context;
    krb_check(nullptr, krb5_init_secure_context(out(context)), "test context");
    const auto ctx = context.get();
    const auto client = parse_principal(ctx, "alice@DOMAIN.LOCAL"),
               broker = parse_principal(ctx, "broker@DOMAIN.LOCAL");
    expected_client = client.get();
    expected_broker = broker.get();
    krb5_creds evidence{};
    char secret[] = "PRIVATE EVIDENCE";
    evidence.ticket = {.magic = 0, .length = sizeof(secret) - 1, .data = secret};
    const auto acquire = [&]
    {
        requests = 0;
        ScopeExit restore_clock([]() noexcept { time_offset = 0; });
        return delegate_services(ctx, cfg, client.get(), broker.get(), nullptr, evidence);
    };
    const auto inspect = [&](ByteView bytes, bool due)
    {
        const auto file = memory_file("delegation-test", bytes);
        auto cache = krb_owner<std::remove_pointer_t<krb5_ccache>, krb5_cc_close>(ctx);
        krb_check(ctx, krb5_cc_resolve(ctx, std::format("FILE:/proc/self/fd/{}", file.get()).c_str(), out(cache)),
                  "parse delegated FILE cache");
        KrbPrincipal principal(nullptr, {ctx});
        krb_check(ctx, krb5_cc_get_principal(ctx, cache.get(), out(principal)), "cache principal");
        need(krb5_principal_compare(ctx, principal.get(), client.get()), "wrong cache owner");
        krb5_cc_cursor cursor{};
        krb_check(ctx, krb5_cc_start_seq_get(ctx, cache.get(), &cursor), "read service cache");
        ScopeExit finish([&]() noexcept { krb5_cc_end_seq_get(ctx, cache.get(), &cursor); });
        unsigned count = 0;
        for (;;)
        {
            krb5_creds cred{};
            ScopeExit free([&]() noexcept { krb5_free_cred_contents(ctx, &cred); });
            const auto code = krb5_cc_next_cred(ctx, cache.get(), &cursor, &cred);
            if (code == KRB5_CC_END) break;
            krb_check(ctx, code, "read service");
            need(count < cfg.service_spns.size(), "extra credential leaked into cache");
            const auto target = parse_principal(ctx, cfg.service_spns[count++]);
            validate_service_credential(ctx, cred, client.get(), target.get(), time(nullptr));
        }
        need(count == 2, "missing service credential");
        maintain::Result result;
        const auto plan = maintain::service_schedule(ctx, cache.get(), client.get(), result);
        need(result.service_only && result.renew == 0 &&
                 plan.action == (due ? maintain::Action::Enroll : maintain::Action::Idle),
             "service batch was renewed or its earliest expiry was ignored");
    };

    test("multiple service tickets round-trip without broker TGT or S4U evidence",
         [&]
         {
             auto bytes = acquire();
             ScopeExit erase([&]() noexcept { wipe(bytes); });
             need(requests == 2, "incorrect request count");
             inspect(bytes, false);
         });
    for (const auto failure : {"denied", "broker", "tgt", "envelope", "excess", "rc4", "expired batch"})
        test(std::string("delegation rejects ") + failure,
             [&]
             {
                 scenario = failure;
                 rejects([&] { (void)acquire(); });
             });
    test("maintenance refreshes the batch at its earliest service expiry without renewal",
         [&]
         {
             scenario = "expiry";
             auto bytes = acquire();
             ScopeExit erase([&]() noexcept { wipe(bytes); });
             inspect(bytes, true);
         });
    test("maintenance does not report a partially validated service cache as usable",
         [&]
         {
             scenario.clear();
             auto bytes = acquire();
             ScopeExit erase([&]() noexcept { wipe(bytes); });
             const auto file = memory_file("service-cache-fixture", bytes);
             auto cache = krb_owner<std::remove_pointer_t<krb5_ccache>, krb5_cc_close>(ctx);
             krb_check(ctx,
                       krb5_cc_resolve(ctx, std::format("FILE:/proc/self/fd/{}", file.get()).c_str(), out(cache)),
                       "parse service cache");
             KrbCache damaged(nullptr, {ctx});
             krb_check(ctx, krb5_cc_new_unique(ctx, "MEMORY", nullptr, out(damaged)), "damaged cache");
             krb_check(ctx, krb5_cc_initialize(ctx, damaged.get(), client.get()), "damaged cache principal");
             for (const auto &spn : cfg.service_spns)
             {
                 const auto target = parse_principal(ctx, spn);
                 krb5_creds match{}, cred{};
                 ScopeExit free([&]() noexcept { krb5_free_cred_contents(ctx, &cred); });
                 match.client = client.get();
                 match.server = target.get();
                 krb_check(ctx, krb5_cc_retrieve_cred(ctx, cache.get(), 0, &match, &cred), "fixture ticket");
                 if (spn == cfg.service_spns.back()) cred.ticket_flags |= TKT_FLG_INVALID;
                 krb_check(ctx, krb5_cc_store_cred(ctx, damaged.get(), &cred), "store damaged ticket");
             }
             maintain::Result result;
             rejects([&] { (void)maintain::service_schedule(ctx, damaged.get(), client.get(), result); });
             need(result.end == 0 && !result.success, "partial validation reported usable credentials");
         });
    return testing::finish("Synthetic KDC responses; real cache serialization and maintenance inspection.");
}
