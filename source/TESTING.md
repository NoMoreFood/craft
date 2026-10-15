# CRAFT deployment validation

Validate the installed system with disposable, nonprivileged identities before production use. A successful build or offline check does not establish the deployed CA policy, KDC mapping, directory delegation or scheduler behavior. Record the source revision, OS/packages, configuration, commands and results for your deployment.

Use the [mode 1 setup](README.md#mode-1-setup-privileged-certificate-enrollment), [mode 2 setup](README.md#mode-2-setup-privileged-credential-linking) or [mode 3 setup](README.md#mode-3-setup-unprivileged-windows-exported-certificate), then complete the common checks and that mode's checklist below.

## Offline checks

Compile with the [build dependencies](README.md#build), then run from the repository root:

```sh
cmake -S source -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

CTest covers configuration, certificate/response parsing, home-file safety, ticket policy, cache serialization, audit/diagnostic behavior synthetic Key Trust cleanup and constrained-delegation cache handling. These checks use synthetic credentials and mocked directory operations. They do not contact AD, AD CS or CES and do not prove installed setuid behavior or live PKINIT.

### Windows helper checks

From the repository root in Windows PowerShell:

```powershell
.\scripts\Test-Configure-CRAFT-CA.ps1
.\scripts\Test-Request-CRAFT-Certificate.ps1
.\scripts\Test-Grant-CRAFTKeyCredentialLink.ps1
```

These checks do not modify AD or contact a CA. The certificate helper checks create and remove synthetic current-user certificates, private keys and export files. They cover export/reuse, renewal, ACLs, interrupted publication/recovery, shared-key preservation, queued store deletion and pending/denied requests. Delegation checks verify the rule's exact rights and scope. Provisioning checks cover parameters, commands and certificate selection. Use a disposable Windows test profile.

## Common installed-system checks

| Check | Required observation |
| --- | --- |
| Identity and execution | Run as the intended non-root user without `sudo`. NSS name/home select the fixed `<Linux username>@<realm>` principal; arguments and forged environment values cannot choose another identity. |
| Cache | Inspect the returned `FILE:` cache. It is caller-owned mode 0600 in the NSS home and unreadable by other UIDs. Acquisition/validation failure preserves its previous content. |
| Ticket | Modes 1-3: verify Initial/Pre-authenticated flags, no forwardable/proxiable flags, AES256/AES128 session and ticket encryption, actual validity and renewal deadline. Expect Renewable only when renewal is configured. Mode 4: verify exact service SPNs with no TGT/evidence; S4U forwardable/forwarded flags may be present. |
| Trust and mapping | Verify the pinned KDC. Modes 1-3: verify current CA/KDC CRLs, configured EKU/identity checks and the deployed strong account mapping. Wrong-account, revoked-certificate and stale/missing-required-CRL attempts fail. |
| Lifetime | Compare actual grants with configured requests. Mode 4 accepts shorter service grants. In modes 1-3, strict mode rejects shorter initial/renewal grants; permissive mode warns. Excessive lifetimes or non-AES grants always fail. |
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

## Live acceptance checklist

These checks apply to **mode 1 enrollment**. Test with both home PEM files absent so supplied credentials cannot hide incomplete enrollment setup.

1. Verify the launcher is `root:craft-users` mode 4750, the worker/maintainer are ordinary executables, private credentials are `root:craft` mode 0640 and `/run/craft` is `craft:craft` mode 0700. Callers must not belong to the service group or invoke its credentials directly.
2. Verify the service principal/AES keytab, GC DNS/SPN/search base and SASL GSSAPI plugin. Resolve exactly one intended account, including an alternate UPN suffix where used; unknown/ambiguous users fail. Both CES authentication modes require the directory keytab.
3. Validate the actual CES endpoint, HTTPS chain and optional CES CRLs. For Negotiate, verify SPNEGO, HTTP SPN, Kerberos-only transport and constrained delegation; for mTLS, verify the separate mapped client pair.
4. Inspect a successful issued certificate: matching key, resolved UPN, configured template OID, CA-generated SID/strong mapping, all three client EKUs, non-CA usage and total validity including backdating. Confirm requested CN behavior does not change account identity.
5. Prove CA refusal for out-of-scope recipients, privileged targets, unauthorized templates/signers and missing qualifying signatures. Make prohibited requests otherwise valid so denial demonstrates policy. Follow [enrollment-agent denial tests](../docs/03-Enrollment-Agent-Restrictions.md#prove-denial-at-the-ca).
6. Confirm wrong UPN/template/key, missing EKUs, revoked agent/user certificate, expired required CRLs and excessive validity fail without replacing the cache. Timeouts can leave CA issuance records; CRAFT does not cancel/revoke issuance.
7. Exercise installed setuid behavior, `nosuid`/`no_new_privs` rejection, the per-UID interval including failed attempts, concurrent requests and worker termination. Correlate AUTHPRIV, CA/CES and KDC records.
8. If maintenance is used, test renewal after the enrolled certificate expires and fresh enrollment across the renewal deadline with the actual job scheduler. Confirm CA issuance volume and the ability to disable acquisition separately from renewal.

## Key Trust acceptance checks

These checks apply to **mode 2**. Use disposable ordinary accounts and both home PEM files absent.

1. Pin the same writable DC for `kt_dc_url` and Kerberos. Verify Key Trust capability, KDC certificate/CRLs, MIT PKINIT freshness interoperability, service AES keytab and LDAP/GSSAPI encryption at SSF 128 or higher.
2. Inspect the delegation: exactly ReadProperty/WriteProperty on `msDS-KeyCredentialLink` for a reviewed OU or single user. Keep privileged identities outside the scope and protect its membership/ACL administrators.
3. Capture existing legitimate keys, run acquisition, and confirm CRAFT adds then removes only its value. Check the requested principal, ticket policy and a real service authentication.
4. Prove directory refusal for out-of-scope/privileged targets and writes to other attributes. The helper's privileged-target checks do not filter an OU grant if an account later becomes privileged.
5. Fail or interrupt PKINIT, including an uncertain add outcome, and confirm cleanup and cache preservation. Force a cleanup failure in the lab; publication must fail, the CRITICAL log must identify the residual credential, and an administrator must remove only that value.
6. Revoke the helper delegation with `-Remove` and verify fresh acquisition fails after propagation. Test a withdrawn/rotated keytab. Already-issued tickets are a separate concern.
7. Correlate CRAFT add/remove and `certificate_source=key_trust` records with DC events 5136 and 4768. Configure the required directory auditing/SACL; event policy alone is insufficient.

Follow [Key Trust delegation](../docs/04-Key-Credential-Link-Delegation.md) for detailed authorization and cleanup checks.

## Home workflow acceptance checks

These checks apply to **mode 3**, including supplied certificates on a privileged installation.

1. Run the Windows helper as the intended ordinary domain user with an authorized template. Validate eligible-CA selection, exportable software-key policy, pending/denied outcomes and the exported pair's Linux/KDC mapping.
2. Verify ordinary mode-0755 executables, readable root-controlled public configuration/trust/CRLs, and successful acquisition without a service account, private service credentials or `/run/craft`. Test inherited `no_new_privs`.
3. Supply the pair in the NSS home with safe directories, caller ownership and private key permissions. Validate both ordinary certificate validity and alternate UPN suffixes where used.
4. Verify a valid pair takes priority on a privileged installation: no LDAP/CES operation, agent/keytab access or privileged acquisition timestamp is required. Partial/invalid pairs must fail without either privileged mechanism.
5. Reject symlinks, extra hard links, wrong ownership, public private-key permissions, nonregular/empty/oversized files, encrypted/malformed or mismatched keys, invalid profiles and wrong-account mapping. Preserve the previous cache.
6. Remove both files: an ordinary installation must refuse privileged acquisition; a setuid installation must use only its configured mechanism. Neither failure nor a partial pair permits switching modes.
7. Repeat Windows export/reuse/renewal and optional local-store deletion. Transfer replacements only after success and before expiry. Test Linux failure with an incomplete replacement, then restore the valid pair.
8. If maintenance is used, test cache-only renewal, fresh authentication with the replaced pair, outages and watched-job exit. Neither CRAFT nor the maintainer renews the supplied certificate.

## Constrained delegation acceptance checks

These checks apply to **mode 4**. Use a dedicated lab broker and disposable ordinary users.

1. Verify broker SPN/keytab identity, AES keys, protocol transition, `TrustedForDelegation=false`, and the exact AD target SPNs. Keep broker permissions separate from enrollment and Key Trust.
2. Run with `mechanism=constrained_delegation`, at least two approved targets, and both absent and present home PEM pairs. A valid or invalid home pair must not select PKINIT. No CA/CRL files, LDAP or CES credentials are required.
3. Inspect every FILE-cache credential with MIT Kerberos: the client must be the Linux caller and every server an exact configured target. No `krbtgt`, broker credential, S4U2Self `second_ticket`, or proxy metadata may be present. Check AES ticket/session encryption and the lifetime cap.
4. Authenticate to a real approved service with the published cache. Attempt an uncached, unapproved SPN; it must fail because the cache contains no TGT.
5. Configure one approved and one AD-denied target. Acquisition must fail as a batch and preserve the previous cache byte-for-byte. Repeat with a nondelegable user, disabled protocol transition, withdrawn delegation, wrong keytab and unavailable KDC.
6. Verify ordinary non-setuid installation fails even with valid home credentials. Exercise setuid caller/runtime/cache permissions and the per-user rate limit. Audit records must identify `mechanism=constrained_delegation` and the service count without credential bytes.
7. Use short service lifetimes to exercise actual broker refresh through `craft-maintain`. Check earliest expiry, replacement of the complete batch, no TGT renewal, status and watched-job exit. Verify outage retries preserve the cache and recover after service returns.
8. When switching from modes 1-3, stop prior maintainers and remove the old TGT cache. Delegation removal and cache deletion do not revoke previously issued tickets.

The `constrained-delegation` CTest suite substitutes KDC responses while using real MIT cache encoding/parsing. It checks batch failure, caller/target/envelope validation, AES/lifetime enforcement, evidence removal and service maintenance scheduling. Live AD results must be recorded separately.

## Recorded validation

These are recorded repository observations, not acceptance results for your current build or deployment.

### Service-only validation

The Ubuntu 24.04.5 Hyper-V client built the mode 4 implementation with GCC 13.3 and MIT Kerberos 1.20.1. All three CTest suites passed as root and as an ordinary user: offline checks, Key Trust cleanup and nine constrained-delegation checks. The delegation suite substitutes KDC responses; it does not prove AD delegation authorization.

The nine delegation checks also passed with AddressSanitizer and UndefinedBehaviorSanitizer. Detached-maintainer integration passed 18 checks with pidfd watching and 18 with the `/proc` fallback, including service-only startup/status and refresh without TGT renewal. These runs used synthetic credentials and a private mount namespace for the test issuer, home, audit socket and Kerberos policy.

An isolated installed launcher/worker on that client reached the Windows AD KDC for S4U2Self, rejected an unknown user, preserved the existing cache and ignored an invalid home PEM pair. An ordinary non-setuid installation refused service-only acquisition. These are denial and process-boundary observations; successful Windows broker delegation, real service access, live broker refresh and additional guest coverage require the lab broker to be configured and tested.

### Multi-OS validation

A DISA STIG-hardened AD lab used Ubuntu 24.04.5 LTS and Rocky Linux 9.8 clients, Windows Server 2022 AD/AD CS/CES, and Server 2019/2025 member servers. RSA 2048/3072/4096-bit keys were covered in modes 1-3; all 27 checks passed.

| Mode | Recorded coverage | Passed |
| --- | --- | --- |
| 1 Enrollment | CES EOBO and PKINIT on both Linux clients | 6/6 |
| 2 Key Trust | PKINIT and temporary-key cleanup on both Linux clients | 6/6 |
| 3 Windows export | Nine exports on Server 2019/2022/2025; six Linux PKINIT runs | 15/15 |

The lab confirmed ten-hour TGTs with seven-day renewal, AES256 session/ticket encryption, LDAP/GSSAPI and SMB access, scoped nonadministrative delegation, and launcher/runtime/cache permissions. The earlier Windows Server 2022/Ubuntu enrollment trial also recorded successful manual TGT renewal. These observations do not establish every CA, mapping policy or denial case.

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
