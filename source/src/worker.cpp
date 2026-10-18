// Unprivileged credential worker. The public entry point is launcher.cpp.
#include "delegation.hpp"
#include "directory.hpp"
#include "enroll.hpp"
#include "pkinit.hpp"

namespace
{
using namespace craft;

// The service account's private runtime directory holds only per-user issuance locks and timestamps.
Fd runtime_directory()
{
    Fd dir(open(RUNTIME_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    sysneed(dir.get() >= 0, "open private runtime directory");
    need(owned_directory(dir.get(), getuid(), 0077),
         "runtime directory must be dedicated-account owned, mode 0700");
    return dir;
}

// Enroll a fresh certificate for the fixed directory identity, signed by the verified enrollment agent.
UserIdentity enroll(Kerberos &krb, const Config &cfg, Mapping &m)
{
    const Cert agent = load_cert("agent.pem");
    const Key agent_key = load_key("agent.key");
    need(has_eku(agent.get(), AGENT_OID), "agent certificate lacks Certificate Request Agent EKU");
    sslneed(X509_check_private_key(agent.get(), agent_key.get()) == 1, "agent key mismatch");
    verify_chain(agent.get());
    krb.acquire_transport(cfg);
    m = directory_lookup(ldap_connect(cfg.gc_url).get(), cfg, cfg.gc_base_dn, m.name);
    UserIdentity identity{.certificate = nullptr, .key = generate_key(cfg.key_bits)};
    const Req req =
        make_request(identity.key.get(), m.upn, cfg.template_oid, common_name(cfg, m.name, m.upn));
    const Bytes cms = wrap_eobo(req.get(), agent.get(), agent_key.get(), cfg.netbios + "\\" + m.name);
    identity.certificate = parse_response(send_ces(cfg, soap_request(cfg, cms)), identity.key.get());
    return identity;
}
} // namespace

int main(int argc, char **argv)
{
    program = "craft-worker";
    uid_t requesting_uid = 0;
    const pid_t request = getppid(); // the launcher, whose own records carry this number
    KeyCredentialGuard published;
    bool may_continue = true, credentials_ready = false;
    try
    {
        // Reset inherited state and select the caller or dedicated-account workflow.
        const std::string_view mode = argc == 5 ? argv[1] : "";
        const bool home = mode == "home", policy = mode == "policy";
        const auto selected = std::ranges::find(MODE_NAMES, mode);
        need(policy || selected != MODE_NAMES.end(), "worker is not a public interface; use craft");
        const std::string_view attempt = argv[4];
        need(attempt.size() == 32 && attempt.find_first_not_of("0123456789abcdef") == attempt.npos,
             "invalid acquisition identifier");
        sysneed(clearenv() == 0 && setenv("KRB5_CONFIG", path("krb5.conf").c_str(), 1) == 0 &&
                    setenv("HOME", "/nonexistent", 1) == 0 && setenv("LANG", "C", 1) == 0,
                "set worker environment");
        no_core();
        signal(SIGALRM, SIG_DFL);
        alarm(policy ? 30 : 90);

        // End with the launcher: its death, or its abandoning this worker, closes the pipe that is our input.
        exit_with_peer(STDIN_FILENO);
        const rlimit cpu{30, 30}, memory{512 * 1024 * 1024, 512 * 1024 * 1024};
        sysneed(setrlimit(RLIMIT_CPU, &cpu) == 0 && setrlimit(RLIMIT_AS, &memory) == 0,
                "worker resource limits");

        // Re-resolve the runtime UID and validate the requesting account.
        requesting_uid = number(argv[2]);
        Mapping m{.name = argv[3], .upn = {}};
        need(requesting_uid != 0 && simple_name(m.name), "invalid requesting account");
        const Account caller = lookup_uid(requesting_uid);
        need(caller.name == m.name, "runtime UID/name changed; administrator review required");
        const Config cfg = config(policy ? std::optional<CertificateSource>{}
                                         : static_cast<CertificateSource>(selected - MODE_NAMES.begin()));
        const bool delegated = cfg.source == CertificateSource::ConstrainedDelegation;
        UserIdentityFiles files;
        if (home || policy)
        {
            need(getuid() == requesting_uid && geteuid() == requesting_uid && getgid() == getegid(),
                 "policy and home workers must run as the caller");
            if (policy)
            {
                Bytes modes;
                for (const auto item : cfg.modes)
                    modes.push_back(static_cast<unsigned char>(item));
                write_all(STDOUT_FILENO, modes);
                return 0;
            }
            files = user_identity_files(caller);
            need(files.certificate.get() >= 0, "home certificate pair is absent");
        }
        else
        {
            // Restrict broker acquisition to the dedicated account.
            const Account svc = service_account();
            need(requesting_uid != svc.uid && getuid() == svc.uid && geteuid() == svc.uid &&
                     getgid() == svc.gid && getegid() == svc.gid,
                 "privileged worker must run with dedicated account credentials");
        }

        // Only CA enrollment uses libcurl; balance its initialization across normal and exceptional exits.
        const bool enrollment = cfg.source == CertificateSource::Enrollment;
        if (enrollment) need(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK, "curl initialize");
        ScopeExit cleanup_curl(
            [enrollment]() noexcept
            {
                if (enrollment) curl_global_cleanup();
            });
        Fd lock;
        if (!home)
            lock =
                rate_limit(runtime_directory().get(), requesting_uid, cfg.interval, time(nullptr), attempt);
        if (!delegated)
        {
            require_trusted(path("kdc-trust.pem"));
            require_trusted(path("kdc-crls.pem"));
        }

        // Keep the caller principal fixed across PKINIT and constrained delegation.
        Kerberos krb;
        Bytes result;
        ScopeExit erase([&]() noexcept { wipe(result); });
        time_t end = 0;
        if (delegated) result = get_service_tickets(krb, cfg, m);
        else
        {
            // Acquire and validate the certificate identity; confirm Key Trust cleanup before release or fallback.
            UserIdentity identity;
            Cert kt_ca;
            if (home) identity = load_user_identity(files);
            else if (enrollment) identity = enroll(krb, cfg, m);
            else
            {
                // Key Trust: write a public key to the directory, authenticate with it, then remove it.
                krb.acquire_transport(cfg);
                m = directory_lookup(
                    ldap_connect(cfg.kt_dc_url).get(), cfg, domain_to_dn(cfg.domain), m.name);
                identity.key = generate_key(cfg.key_bits);
                auto pair = make_key_trust_pair(
                    identity.key.get(), common_name(cfg, m.name, m.upn), m.upn, cfg.tgt + 3600);
                identity.certificate = std::move(pair.leaf);
                kt_ca = std::move(pair.ca);
                const auto blob = key_credential_blob(identity.key.get(), KEY_TRUST_DEVICE_ID, time(nullptr));
                published.publish(cfg, m.object_ref, dn_binary(blob, m.object_ref), lock.get());
            }

            // The Key Trust certificate is authorized by the directory write, not a CA chain.
            if (cfg.source != CertificateSource::KeyTrust) verify_chain(identity.certificate.get());
            end = validate_leaf(identity.certificate.get(), identity.key.get(), m, cfg);
            result = get_tgt(krb, cfg, m, identity.certificate.get(), identity.key.get(), kt_ca.get());

            // Remove the Key Trust key before any credential bytes leave this process.
            may_continue = false;
            published.withdraw();
            may_continue = true;
        }
        if (delegated)
            audit(LOG_NOTICE,
                  std::format("issued service tickets request={} uid={} user={} mechanism={} services={}",
                              request,
                              requesting_uid,
                              m.name,
                              mode,
                              cfg.service_spns.size()));
        else
            audit(LOG_NOTICE,
                  std::format(
                      "issued TGT request={} uid={} user={} certificate_source={} certificate_expiry={}",
                      request,
                      requesting_uid,
                      m.name,
                      mode,
                      end));

        // Signal readiness only after validation, directory cleanup and audit have all succeeded.
        const unsigned char ready = 1;
        credentials_ready = true;
        write_all(STDOUT_FILENO, {&ready, 1});
        write_all(STDOUT_FILENO, result);
        return 0;
    }
    catch (const std::exception &e)
    {
        try
        {
            published.withdraw();
        }
        catch (const std::exception &cleanup)
        {
            may_continue = false;
            report(cleanup, std::format("cleanup request={} uid={}", request, requesting_uid));
        }
        report(e, std::format("issuance request={} uid={}", request, requesting_uid));
        if (!credentials_ready)
        {
            const unsigned char failed = may_continue ? 0 : 2;
            (void)retry([&] { return write(STDOUT_FILENO, &failed, 1); });
        }
        return 1;
    }
}
