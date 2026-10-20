# CRAFT deployment validation

Validate the installed system with disposable, nonprivileged identities before production use. A successful build or offline check does not establish the deployed CA policy, KDC mapping, directory delegation or scheduler behavior. Record the source revision, OS/packages, configuration, commands and results for your deployment.

Use the [Enrollment Agent setup](README.md#enrollment-agent-setup), [Key Trust setup](README.md#key-trust-setup), [BYOC setup](README.md#byoc-setup) or [Constrained Delegation setup](README.md#constrained-delegation-setup), then complete the common checks and that mode's checklist below.

## Offline checks

Compile with the [build dependencies](README.md#build), then run from the repository root:

```sh
cmake -S source -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

CTest covers configuration, certificate/response parsing, home-file safety, ticket policy, cache serialization, audit/diagnostic behavior, synthetic Key Trust cleanup and constrained-delegation cache handling. These checks use synthetic credentials and mocked directory operations. They do not contact AD, AD CS or CES and do not prove installed setuid behavior or live PKINIT.

### Windows helper checks

From the repository root in Windows PowerShell:

```powershell
.\scripts\Test-Configure-CRAFT-CA.ps1
.\scripts\Test-Request-CRAFT-Certificate.ps1
.\scripts\Test-Grant-CRAFTKeyCredentialLink.ps1
```

These checks do not modify AD or contact a CA. The certificate helper checks create and remove synthetic current-user certificates, private keys and export files. They cover export/reuse, renewal, ACLs, interrupted publication/recovery, shared-key preservation, queued store deletion and pending/denied requests. Delegation checks verify the rule's exact rights and scope. Provisioning checks cover parameters, commands and certificate selection. Use a disposable Windows test profile.

## Optional GSS-Proxy checks

The [application integration guide](../docs/06-GSS-Proxy-and-SELinux.md) includes the host setup and deployment acceptance checks. In a **fresh disposable Ubuntu container only**, install the normal build dependencies plus `gssproxy`, `krb5-kdc`, `krb5-admin-server`, `krb5-user` and `python3-gssapi`, then build and run:

```sh
cmake -S source -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
CRAFT_DISPOSABLE_CONTAINER=yes python3 source/tests/gssproxy-integration.py build
```

Run the integration script as root only inside that disposable container. It creates synthetic issuer/consumer accounts, a private home and MIT KDC under fixed test paths, starts a dedicated proxy, and temporarily removes the packaged interposer configuration for a denial check. It requires the Ubuntu package path `/etc/gss/mech.d/proxymech.conf`. Discard the container after the run.

The checks exercise actual Kerberos and SPNEGO authentication with encrypted messages, consumer denial of direct cache reads, UID restrictions, inherited environment replacement, atomic source-cache replacement, exact service-only targets, uncached-target denial, missing credentials/interposer/socket and daemon failure. The fixtures model CRAFT's published cache; they do not perform AD acquisition or S4U exchanges. The existing mode-specific suites and live acceptance checks cover those acquisition paths.

For SELinux, compile `source/selinux/craft_gssproxy.te` against the deployment distribution's `selinux-policy-devel` package, then run the guide's acceptance checks on an enforcing host. A successful module build in a container does not establish application confinement, label inheritance or access decisions on the deployed kernel.

## Common installed-system checks

| Check | Required observation |
| --- | --- |
| Identity and execution | Run as the intended non-root user without `sudo`. NSS name/home select the fixed `<Linux username>@<realm>` principal; arguments and forged environment values cannot choose another identity. |
| Cache | Inspect the returned `FILE:` cache. It is caller-owned mode 0600 in the NSS home and unreadable by other UIDs. Acquisition/validation failure preserves its previous content. |
| Ticket | Certificate modes: verify Initial/Pre-authenticated flags, no forwardable/proxiable flags, AES256/AES128 session and ticket encryption, actual validity and renewal deadline. Expect Renewable only when renewal is configured. Constrained Delegation: verify exact service SPNs with no TGT/evidence; S4U forwardable/forwarded flags may be present. |
| Trust and mapping | Verify the pinned KDC. Certificate modes: verify current CA/KDC CRLs, configured EKU/identity checks and the deployed strong account mapping. Wrong-account, revoked-certificate and stale/missing-required-CRL attempts fail. |
| Lifetime | Compare actual grants with configured requests. Constrained Delegation accepts shorter service grants. In certificate modes, strict mode rejects shorter initial/renewal grants; permissive mode warns. Excessive lifetimes or non-AES grants always fail. |
| Application access | Obtain a service ticket and authenticate to a real authorized SMB, LDAP or Kerberos-enabled web service. Application access follows the account's permissions. |
| Failure and concurrency | Exercise KDC/network outage, interrupted acquisition, concurrent runs, unsafe/writable home paths and insufficient disk space. Only validated credentials are published. |
| Audit | Correlate launcher, worker and maintenance AUTHPRIV records. Confirm failure when the logging service is unavailable. Verify host audit rules, retention and forwarding on the installed host. |
| Maintenance, if used | Test actual scheduler/application renewal, fresh authentication near the renewal deadline, KDC/credential outages, concurrent jobs, credential reload and exit of the watched PID. Later failures appear in status/logs and do not terminate the job. |

Run acquisition and inspect tickets as the test user:

```sh
cache=$(/usr/local/bin/craft) || exit "$?"
export KRB5CCNAME="$cache"
klist -ef -c "$KRB5CCNAME"
stat -c '%U %a %n' ~/.krb5cc_craft
```

Configure system Kerberos for applications and maintenance as well as CRAFT's acquisition configuration. Do not infer ten-hour/seven-day grants from requested values alone.

## Mode selection acceptance checks

Validate each mode alone before combining them. Then test the exact ordered list intended for deployment.

1. Confirm the first successful mode supplies the cache and later modes are not attempted. Reverse the order and verify the selected mode in AUTHPRIV records.
2. Cause a reported acquisition failure in each preferred mode and verify the next enabled mode runs. Include absent, partial, invalid and unsafe home pairs, server denial and unavailable endpoints. Disabled modes must never run.
3. Verify broker attempts within one invocation share the per-user cooldown, while a new invocation cannot reuse that admission. Check concurrent requests and directory cleanup.
4. Reject an invalid configuration before acquisition, including missing prerequisites for a later mode. Worker termination, unconfirmed Key Trust cleanup and cache-publication failure must stop fallback and preserve the cache.
5. When both credential kinds are enabled, exercise automatic maintenance from service tickets to a TGT through fallback. Verify status, renewal deadlines, application access and watched-job exit. Use only `constrained_delegation` if policy prohibits a TGT.

## Live acceptance checklist

These checks apply to **Enrollment Agent**. Set `modes=enrollment` so other modes cannot hide incomplete enrollment setup.

1. Verify the launcher is `root:craft-users` mode 4750, the worker/maintainer are ordinary executables, private credentials are `root:craft` mode 0640 and `/run/craft` is `craft:craft` mode 0700. Callers must not belong to the service group or invoke its credentials directly.
2. Verify the service principal/AES keytab, GC DNS/SPN/search base and SASL GSSAPI plugin. Resolve exactly one intended account, including an alternate UPN suffix where used; unknown/ambiguous users fail. Both CES authentication modes require the directory keytab.
3. Validate the actual CES endpoint, HTTPS chain and optional CES CRLs. For Negotiate, verify SPNEGO, HTTP SPN, Kerberos-only transport and constrained delegation; for mTLS, verify the separate mapped client pair.
4. Inspect a successful issued certificate: matching key, resolved UPN, configured template OID, CA-generated SID/strong mapping, all three client EKUs, non-CA usage and total validity including backdating. Confirm requested CN behavior does not change account identity.
5. Prove CA refusal for out-of-scope recipients, privileged targets, unauthorized templates/signers and missing qualifying signatures. Make prohibited requests otherwise valid so denial demonstrates policy. Follow [enrollment-agent denial tests](../docs/03-Enrollment-Agent-Restrictions.md#prove-denial-at-the-ca).
6. Confirm wrong UPN/template/key, missing EKUs, revoked agent/user certificate, expired required CRLs and excessive validity fail without replacing the cache. Timeouts can leave CA issuance records; CRAFT does not cancel/revoke issuance.
7. Exercise installed setuid behavior, `nosuid`/`no_new_privs` rejection, the per-UID interval including failed attempts, concurrent requests and worker termination. Correlate AUTHPRIV, CA/CES and KDC records.
8. If maintenance is used, test renewal after the enrolled certificate expires and fresh enrollment across the renewal deadline with the actual job scheduler. Confirm CA issuance volume and the ability to disable acquisition separately from renewal.

## Key Trust acceptance checks

These checks apply to **Key Trust**. Use disposable ordinary accounts and `modes=key_trust`.

1. Pin the same writable DC for `kt_dc_url` and Kerberos. Verify Key Trust capability, KDC certificate/CRLs, MIT PKINIT freshness interoperability, service AES keytab and LDAP/GSSAPI encryption at SSF 128 or higher.
2. Inspect the delegation: exactly ReadProperty/WriteProperty on `msDS-KeyCredentialLink` for a reviewed OU or single user. Keep privileged identities outside the scope and protect its membership/ACL administrators.
3. Capture existing legitimate keys, run acquisition, and confirm CRAFT adds then removes only its value. Check the requested principal, ticket policy and a real service authentication.
4. Prove directory refusal for out-of-scope/privileged targets and writes to other attributes. The helper's privileged-target checks do not filter an OU grant if an account later becomes privileged.
5. Fail or interrupt PKINIT, including an uncertain add outcome, and confirm cleanup and cache preservation. Force a cleanup failure in the lab; publication must fail, the CRITICAL log must identify the residual credential, and an administrator must remove only that value.
6. Revoke the helper delegation with `-Remove` and verify fresh acquisition fails after propagation. Test a withdrawn/rotated keytab. Already-issued tickets are a separate concern.
7. Correlate CRAFT add/remove and `certificate_source=key_trust` records with DC events 5136 and 4768. Configure the required directory auditing/SACL; event policy alone is insufficient.

Follow [Key Trust delegation](../docs/04-Key-Credential-Link-Delegation.md) for detailed authorization and cleanup checks.

## Home workflow acceptance checks

These checks apply to **BYOC**, including supplied certificates on a privileged installation.

1. Run the Windows helper as the intended ordinary domain user with an authorized template. Validate eligible-CA selection, exportable software-key policy, pending/denied outcomes and the exported pair's Linux/KDC mapping.
2. Verify ordinary mode-0755 executables, readable root-controlled public configuration/trust/CRLs, and successful acquisition without a service account, private service credentials or `/run/craft`. Test inherited `no_new_privs`.
3. Supply the pair in the NSS home with safe directories, caller ownership and private key permissions. Validate both ordinary certificate validity and alternate UPN suffixes where used.
4. With `modes=home`, verify that valid pairs need no LDAP/CES operation, agent/keytab access or privileged acquisition timestamp. Partial/invalid pairs must fail and preserve the cache.
5. Reject symlinks, extra hard links, wrong ownership, public private-key permissions, nonregular/empty/oversized files, encrypted/malformed or mismatched keys, invalid profiles and wrong-account mapping. Preserve the previous cache.
6. Remove both files and confirm home-only policy fails. With an explicitly enabled broker fallback, verify that absent, partial and malformed pairs advance to that mode. Reverse the order and confirm successful broker acquisition does not inspect home files.
7. Repeat Windows export/reuse/renewal and optional local-store deletion. Transfer replacements only after success and before expiry. Test Linux failure with an incomplete replacement, then restore the valid pair.
8. If maintenance is used, test cache-only renewal, fresh authentication with the replaced pair, outages and watched-job exit. Neither CRAFT nor the maintainer renews the supplied certificate.

## Constrained delegation acceptance checks

These checks apply to **Constrained Delegation**. Use a dedicated lab broker and disposable ordinary users.

1. Verify broker SPN/keytab identity, AES keys, protocol transition, `TrustedForDelegation=false`, and the exact AD target SPNs. Keep broker permissions separate from enrollment and Key Trust.
2. Run with `modes=constrained_delegation`, at least two approved targets, and both absent and present home PEM pairs. A valid or invalid home pair must not select PKINIT. No CA/CRL files, LDAP or CES credentials are required.
3. Inspect every FILE-cache credential with MIT Kerberos: the client must be the Linux caller and every server an exact configured target. No `krbtgt`, broker credential, S4U2Self `second_ticket`, or proxy metadata may be present. Check AES ticket/session encryption and the lifetime cap.
4. Authenticate to a real approved service with the published cache. Attempt an uncached, unapproved SPN; it must fail because the cache contains no TGT.
5. Configure one approved and one AD-denied target. Acquisition must fail as a batch and preserve the previous cache byte-for-byte. Repeat with a nondelegable user, disabled protocol transition, withdrawn delegation, wrong keytab and unavailable KDC.
6. Verify ordinary non-setuid installation fails even with valid home credentials. Exercise setuid caller/runtime/cache permissions and the per-user rate limit. Audit records must identify `mechanism=constrained_delegation` and the service count without credential bytes.
7. Use short service lifetimes to exercise actual broker refresh through `craft-maintain`. Check earliest expiry, replacement of the complete batch, no TGT renewal, status and watched-job exit. Verify outage retries preserve the cache and recover after service returns.
8. When switching from certificate modes, stop prior maintainers and remove the old TGT cache. Delegation removal and cache deletion do not revoke previously issued tickets.

The `constrained-delegation` CTest suite substitutes KDC responses while using real MIT cache encoding/parsing. It checks batch failure, caller/target/envelope validation, AES/lifetime enforcement, evidence removal and service maintenance scheduling. Live AD results must be recorded separately.

## Recorded validation

These are recorded repository observations, not acceptance results for your current build or deployment.

### Rocky GSS-Proxy and SELinux validation

The optional integration was exercised on Rocky Linux 9.8 with GSS-Proxy 0.8.4-7.el9, MIT Kerberos 1.21.1-10.el9_8 and targeted SELinux policy 38.1.75-2.el9_8.1. SELinux remained enforcing throughout; neither `gssproxy_t` nor the test application domain was permissive. The supplied `craft_gssproxy` module was loaded, the dedicated proxy ran in `gssproxy_t`, and systemd launched the consumer in a separate confined test domain with socket access and no access to `craft_credential_t`. GCC Toolset 15.2.1 built the release targets without warnings and all three CTest suites passed.

A disposable local MIT KDC/CA supplied PKINIT with a certificate and CRL. Actual CRAFT BYOC acquisition produced a 120-second AES256 TGT with a 600-second renewal window in the issuer's mode-0600 cache. The dedicated issuer home, including temporary files, used `craft_credential_t`. System Kerberos configuration was overridden only inside private mount namespaces; the ordinary host realm and packaged proxy instance were preserved. The test configuration disabled short-hostname suffix qualification and allowed one second of clock skew so the expiry check could not succeed merely through the usual grace period.

All 21 enforcing checks passed. They covered Kerberos and SPNEGO mutual authentication with encrypted messages; direct-cache denial for the consumer UID; SELinux denial even when the confined application used the cache owner's UID; unauthorized proxy peers; and replacement of inherited credential selections. Real `craft-maintain` renewal atomically replaced the source inode while retaining issuer ownership, mode 0600, the private SELinux label, the absolute renewal deadline and an issuer-cached service ticket. Fresh consumers authenticated after renewal and after the original ticket expired. Three further CRAFT acquisitions replaced the cache without relabeling, and proxy restart loaded the current credentials. A service-only fixture authenticated to its exact cached target and refused an uncached target. Missing source, interposer and socket checks failed, as did a stopped dedicated daemon with a stale socket, without local credential fallback.

Audit review confirmed enforcing `craft_proxy_test_t` denials on the private issuer directory. It also found `gssproxy_t` denials for `dac_override`: a syscall trace showed successful read-only cache opens and a denied attempt to append a service ticket with `O_RDWR`. Authentication still completed, and the source retained its original TGT without that appended ticket. No capability allowance, permissive domain or generated `audit2allow` policy was added. Service-ticket preservation during renewal was tested with a ticket cached by the issuer.

This validates CRAFT-issued user-cache consumption and real BYOC maintenance against the disposable MIT KDC. The service-only fixture does not exercise AD S4U acquisition or batch refresh. Each authentication uses a fresh consumer process; long-lived opaque credential handles, production application reload behavior and reboot persistence require their own acceptance checks. The [integration guide](../docs/06-GSS-Proxy-and-SELinux.md#deployment-acceptance) describes those deployment checks.

### Four-mode Hyper-V validation

All four modes were exercised on Ubuntu 24.04.5 LTS with GCC 13.3 and MIT Kerberos 1.20.1, and Rocky Linux 9.8 with GCC Toolset 15.2.1 and MIT Kerberos 1.21.1. The lab used Windows Server 2022 AD/AD CS/CES and Server 2019/2025 member servers. Build dependencies were checked against the distribution repositories; Rocky's libcurl packages were updated to 7.76.1-40.el9_8.8. Both release builds completed without warnings.

Each Linux client passed 109 offline checks, 11 synthetic Key Trust cleanup checks and nine constrained-delegation checks as an ordinary user. Detached-maintainer integration passed 19 checks with pidfd watching and 19 with the `/proc` fallback on each client, including interruption of a service refresh without cache loss or incorrect ticket-kind status. Ubuntu also passed all 129 checks across those three suites under AddressSanitizer and UndefinedBehaviorSanitizer, including leak detection. These suites use synthetic credentials and isolated test resources.

Each client passed 55 live acquisition, application, failure and maintenance checks, including 20 ordered-mode checks and two checks of maintenance across a change in credential kind. All three Windows helper suites passed on each Windows guest. The live mode coverage was:

| Mode | Recorded coverage |
| --- | --- |
| Enrollment Agent | CES EOBO and PKINIT with RSA 2048/3072/4096 on both Linux clients |
| Key Trust | PKINIT with all three RSA sizes on both clients; temporary directory keys removed |
| BYOC | Export, reuse, forced renewal and confirmed Windows-store cleanup for all three RSA sizes on Server 2019/2022/2025; all nine exported pairs used for PKINIT on each Linux client |
| Constrained Delegation | Two exact CIFS targets on both clients, with 60-second and default ten-hour service grants; no TGT, broker credential or evidence in the published cache |

Certificate modes produced ten-hour AES TGTs with seven-day renewal, within the configured five-second tolerance, and authenticated to LDAP and both SMB servers. Ordinary non-setuid home mode also succeeded with private broker files absent and inherited `no_new_privs`. With `modes=home`, partial and malformed identities failed and preserved the cache. The maintainer's renewal operation was invoked directly against real ten-hour TGTs from each mode, retaining authentication time, the absolute renewal deadline and usable service tickets; detached startup, status and watched-job exit also passed. A separate short-ticket experiment issued a 120-second TGT but AD refused its renewal with `Ticket expired`; CRAFT retained the cache and reported the failure. Short TGT behavior must be validated against the actual KDC.

Constrained Delegation used a dedicated ordinary broker, protocol transition and exactly two allowed CIFS SPNs, with unconstrained delegation disabled. It ignored malformed and parseable home pairs and ran without CA/CRL configuration. MIT cache inspection verified the fixed caller, exact targets, AES credentials, lifetime bounds and absence of TGTs, broker credentials, S4U2Self evidence and proxy metadata. The ordered-mode run exercised 60- and 36000-second grants; a separate service-only run also exercised 120-second grants. The private broker TGT requested at least 600 seconds for S4U processing.

Both clients read files from both Windows shares using Kerberos-only authentication; server security events confirmed network logons from each client. Ubuntu used Samba `smbclient` 4.19.5. Rocky used `smbprotocol` 1.16.1 with GSSAPI and encrypted SMB because its bundled `smbclient` 4.23.5 required TGT credentials. Case differences between cached SPNs and application requests also prevented service-only authentication. Validate the actual client and exact SPN spelling.

Both clients preserved their cache when a target was denied by AD or the KDC was unreachable. Separate service-only validation also covered a nondelegable user, disabled protocol transition, withdrawn delegation and a wrong broker keytab. An uncached target could not be acquired without a TGT. Rate limits and non-setuid refusal preserved the cache, including when a valid home pair was present. Automatic maintenance refreshed both 60-second service tickets, retained the cache and watched job during a KDC outage, recovered when the KDC returned, and stopped when the job exited. Status reported `ticket_kind=service` and `renew_until=0`.

The ordered-mode checks exercised forward and reverse four-mode lists, first-success short-circuiting, disabled-mode refusal and fallback after absent/partial/invalid/unsafe home identities, CES/LDAP connection failures and an actual AD-denied Key Trust write. Audit records confirmed each attempted mode and the winner. They also verified shared broker admission without bypass by a new invocation, ordinary-installation fallback to home, all-failure cache preservation, up-front validation of later-mode prerequisites, and refusal to continue after cache-publication failure or a killed worker. Automatic maintenance changed a service-only cache to a renewable home-certificate TGT after the preferred delegation attempt failed, updated status, retained LDAP/SMB access and stopped with the watched job.

Temporary AD/Linux identities and test shares were removed, guest credential copies were cleared, and guests started for the run were returned to their original powered-off state. Private mount namespaces kept test binaries, configuration and runtime files separate from the existing installation.

### Linux build and MIT KDC coverage

Recorded warning-free builds and offline/cleanup/maintainer checks cover Ubuntu 24.04 and AlmaLinux 8.10/9 with GCC 13.3 or GCC Toolset 13. Ubuntu checks also passed AddressSanitizer/UndefinedBehaviorSanitizer. Toolset versions here identify test evidence; use a supported compiler for installation.

The audit/parser validation recorded 109 offline checks (106 as an ordinary user), 10 Key Trust cleanup checks and 16 detached-maintainer checks for each job-watch variant. Those counts describe the recorded run; CTest output and current executable results are the evidence for a new build.

Disposable MIT KDC/CA runs exercised installed supplied-certificate acquisition, ten-hour AES256 TGTs with seven-day renewal, usable service tickets, ordinary and setuid installations, wrong-account/revoked/unsafe-pair failures, and environment/NSS selection. Short-ticket trials exercised real renewal, service-ticket preservation, audit correlation, job exit and failure diagnostics. Synthetic detached-maintainer checks covered pidfd and `/proc` watches, startup/status, expiry/rollover, concurrency, backoff and publication failure.

These MIT and synthetic runs did not validate AD/CES, host journald/rsyslog/auditd behavior, or loading the example host audit rules. Offline tests do not cover real directory authorization or PKINIT exchanges.

### Fuzz testing

The recorded Clang/AddressSanitizer/UndefinedBehaviorSanitizer parser run covered configuration/state, PEM/DER identity, SAN/template extensions, CES SOAP, Kerberos ticket envelopes, process-state input and maintainer options. The final 420-second run completed 25,786,400 executions without crash, sanitizer, leak, timeout or out-of-memory findings. This covers CRAFT parsers, not third-party libraries or an installed-system vulnerability assessment. It does not replace live acceptance.

When site policy requires repeating parser assurance, use a disposable Linux build environment with Clang/libFuzzer installed. From the repository root after the ordinary build:

```sh
cmake -S source -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ -DCRAFT_FUZZ=ON
cmake --build build-fuzz --target craft-fuzz -j2
mkdir -p corpus
./build/craft-tests --fuzz-seeds corpus
./build-fuzz/craft-fuzz -max_total_time=420 -max_len=8192 corpus
```

Rejected inputs are expected; crashes, sanitizer reports, leaks, timeouts or out-of-memory stops require review of the saved reproducer. Keep the corpus and record the revision, compiler/libraries, settings, executions and findings. Do not install assurance binaries setuid or substitute them for production executables.

## Operational handover

Assign owners for CRL refresh, service credential rotation, Windows certificate replacement/transfer, Linux account lifecycle, recipient/delegation review, logging and incident response. Record the pinned DC/CES endpoints, approved recipients, effective permissions, expected certificate/ticket policy and actual scheduler behavior. Exercise [acquisition disable and maintainer stop](SECURITY.md#immediate-disable). Removing a credential or cache does not revoke already-issued tickets.
