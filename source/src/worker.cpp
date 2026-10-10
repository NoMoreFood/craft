// Unprivileged certificate worker. The public entry point is launcher.cpp.
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
    struct stat st
    {
    };
    sysneed(fstat(dir.get(), &st) == 0, "stat runtime directory");
    need(st.st_uid == getuid() && (st.st_mode & 0077) == 0,
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
    UserIdentity identity{.certificate = nullptr, .key = generate_key()};
    const Req req =
        make_request(identity.key.get(), m.upn, cfg.template_oid, common_name(cfg, m.name, m.upn));
    const Bytes cms = wrap_eobo(req.get(), agent.get(), agent_key.get(), cfg.netbios + "\\" + m.name);
    identity.certificate = parse_response(send_ces(cfg, soap_request(cfg, cms)), identity.key.get());
    return identity;
}
} // namespace

int main(int argc, char **argv)
{
    uid_t requesting_uid = 0;
    try
    {
        // Reset inherited state and select the caller or dedicated-account workflow.
        const bool home = argc == 4 && std::string_view(argv[1]) == "--home";
        need(home || argc == 3, "worker is not a public interface; use craft");
        sysneed(clearenv() == 0 && setenv("KRB5_CONFIG", path("krb5.conf").c_str(), 1) == 0 &&
                    setenv("HOME", "/nonexistent", 1) == 0 && setenv("LANG", "C", 1) == 0,
                "set worker environment");
        no_core();
        signal(SIGALRM, SIG_DFL);
        alarm(90);
        const rlimit cpu{30, 30}, memory{512 * 1024 * 1024, 512 * 1024 * 1024};
        sysneed(setrlimit(RLIMIT_CPU, &cpu) == 0 && setrlimit(RLIMIT_AS, &memory) == 0,
                "worker resource limits");

        // Re-resolve the runtime UID and validate the requesting account.
        requesting_uid = number(argv[home ? 2 : 1]);
        Mapping m{.name = argv[home ? 3 : 2], .upn = {}};
        need(requesting_uid != 0 && simple_name(m.name), "invalid requesting account");
        const Account caller = lookup_uid(requesting_uid);
        need(caller.name == m.name, "runtime UID/name changed; administrator review required");
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

        // The configuration selects the fallback mechanism when no home pair is present.
        const Config cfg = config(home ? CertificateSource::Home : CertificateSource::Enrollment);
        const CertificateSource source = cfg.source;

        // Only CA enrollment uses libcurl; balance its initialization across normal and exceptional exits.
        const bool enrollment = source == CertificateSource::Enrollment;
        if (enrollment) need(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK, "curl initialize");
        ScopeExit cleanup_curl(
            [enrollment]() noexcept
            {
                if (enrollment) curl_global_cleanup();
            });
        Fd lock;
        if (!home) lock = rate_limit(runtime_directory().get(), requesting_uid, cfg.interval, time(nullptr));
        root_open(path("kdc-trust.pem"));
        root_open(path("kdc-crls.pem"));

        // Keep the caller principal fixed; the KDC enforces certificate-to-account mapping in every mode.
        Kerberos krb;
        Bytes result;
        ScopeExit erase([&]() noexcept { wipe(result); });
        time_t end = 0;
        {
            // Acquire and validate the certificate identity, publishing no Key Trust key beyond this scope.
            UserIdentity identity;
            Cert kt_ca;
            Fd kt_trigger;
            pid_t kt_guardian = -1;
            ScopeExit kt_cleanup(
                [&]() noexcept
                {
                    // Closing the pipe also triggers removal when acquisition throws.
                    kt_trigger = Fd();
                    if (kt_guardian > 0) (void)waitpid_retry(kt_guardian);
                });
            if (home) identity = load_user_identity(files);
            else if (enrollment) identity = enroll(krb, cfg, m);
            else
            {
                // Key Trust: write a public key to the directory, authenticate with it, then remove it.
                krb.acquire_transport(cfg);
                m = directory_lookup(
                    ldap_connect(cfg.kt_dc_url).get(), cfg, domain_to_dn(cfg.domain), m.name);
                identity.key = generate_key(2048);
                auto pair = make_key_trust_pair(
                    identity.key.get(), common_name(cfg, m.name, m.upn), m.upn, cfg.tgt + 3600);
                identity.certificate = std::move(pair.leaf);
                kt_ca = std::move(pair.ca);
                const auto blob = key_credential_blob(identity.key.get(), KEY_TRUST_DEVICE_ID, time(nullptr));
                kt_trigger = start_key_credential_cleanup(
                    cfg, m.object_ref, dn_binary(blob, m.object_ref), kt_guardian, lock.get());
            }

            // The Key Trust certificate is authorized by the directory write, not a CA chain.
            if (source != CertificateSource::KeyTrust) verify_chain(identity.certificate.get());
            end = validate_leaf(identity.certificate.get(), identity.key.get(), m, cfg, source);
            result = get_tgt(krb, cfg, m, identity.certificate.get(), identity.key.get(), kt_ca.get());

            // Remove the Key Trust key before any credential bytes leave this process.
            if (kt_guardian > 0) finish_key_credential_cleanup(kt_trigger, kt_guardian);
        }
        audit(LOG_NOTICE,
              std::format("issued TGT uid={} user={} certificate_source={} certificate_expiry={}",
                          requesting_uid,
                          m.name,
                          home         ? "home"
                          : enrollment ? "enrollment"
                                       : "key_trust",
                          end));
        write_all(STDOUT_FILENO, result);
        return 0;
    }
    catch (const std::exception &e)
    {
        audit(LOG_WARNING, std::format("failed uid={}: {}", requesting_uid, e.what()));
        dprintf(STDERR_FILENO, "craft-worker: %s\n", sanitize_ascii(e.what()).c_str());
        return 1;
    }
}
