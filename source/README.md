# CRAFT - Certificate Request Agent for Tickets

CRAFT obtains Kerberos credentials noninteractively from a trusted, administrator-managed Linux endpoint, including a host that is not domain-joined. Users can supply a certificate and private key in their home directory for an entirely unprivileged workflow. When that pair is absent, an authorized deployment can enroll a short-lived certificate on the user's behalf. Both paths support unattended scripts and Kerberos-aware applications without retaining the user's AD password.

This supports automation alongside MFA-protected interactive sign-in. CRAFT does not perform an MFA challenge or establish that the user completed one. Authentication depends on the supplied certificate and KDC account mapping, or on administrator-authorized enrollment and CA restrictions.

C++20 | Kerberos defaults: 10h TGT, 7d renewal | Home certificates or short-lived enrollment | AES256/AES128.

**Deployment model:** Home mode uses ordinary `craft` and `craft-worker` executables with readable, root-controlled public configuration under `/etc/craft`. Enrollment additionally uses the `craft` service account, `craft-users` caller group, private enrollment credentials and the setuid launcher. Both publish `.krb5cc_craft` in the caller's home.

**Status:** Reference implementation with synthetic offline tests. Live AD/CES/PKINIT interoperability and the installed privilege boundary require an isolated lab trial before production use.

This project supplies native C++20 Linux executables for a host that cannot join an AD domain. It requests a real user TGT through an actual domain controller. It does not forge tickets, use domain ticket-signing secrets, or substitute a service-account TGT for the user's TGT.

Enrollment creates a temporary software certificate; home mode loads the user's existing software certificate and key. Neither workflow implements hardware possession, PIN, attestation or an MFA challenge.

## Process and Access Boundaries

The no-argument launcher identifies the real UID, NSS username and home, ignoring `$USER`, `$HOME`, `SUDO_USER`, `XDG_CONFIG_HOME` and caller-supplied Kerberos configuration. It first starts the fixed worker as the caller to check the home pair. With an ordinary installation, the entire acquisition runs unprivileged. An installed setuid launcher permanently drops its home worker before any home-file access, and drops its cache-writing parent before reading credential bytes.

Only an absent pair selects enrollment. That workflow requires the setuid launcher, runs the worker under the dedicated service account and drops the cache writer to the caller. Enrollment credentials stay separate from the user cache. Invalid home inputs fail without enrollment fallback.

## What Happens

1. Invoke `/usr/local/bin/craft` with no arguments as the intended non-root user, without `sudo`.
2. The caller worker opens the NSS-resolved `~/.config/craft/user.pem` and `user.key`. A complete pair takes priority. Missing directories or both files absent select enrollment; partial, unsafe, malformed, expired or revoked inputs fail.
3. Home mode loads the unencrypted PEM pair as the caller, without a service account, LDAP, submission keytab, enrollment agent, CES or `/run/craft`.
4. Enrollment mode resolves the AD UPN using LDAP/GSSAPI, generates an RSA-3072 key and CSR, signs an EOBO CMS request with `DOMAIN\linuxname`, and submits it through CES over verified HTTPS. [2,3,4,5]
5. Both modes validate matching key, logon usage, current validity, CA trust and CRLs. Enrollment additionally pins the directory UPN, configured template, three client EKUs and short certificate validity.
6. MIT Kerberos performs PKINIT through sealed memory-file copies for `<Linux username>@<realm>`. The KDC enforces account mapping; CRAFT checks the returned principal, TGT flags, AES encryption and lifetimes. [6,8]
7. The caller atomically publishes a mode-0600 `.krb5cc_craft` and prints `FILE:/absolute/path/.krb5cc_craft`.

## Home Certificate Workflow

### Supply the Certificate and Key

Obtain a matching PEM pair through your approved enrollment workflow. The [Windows certificate helper](#request-a-home-certificate-on-windows) can request and export it as the domain user. Transfer the pair securely to Linux, then install it as that Linux user:

```sh
mkdir -p ~/.config/craft
chmod 0700 ~/.config/craft
install -m 0600 /path/to/user-certificate.pem ~/.config/craft/user.pem
install -m 0600 /path/to/user-private-key.pem ~/.config/craft/user.key
```

Both files must be caller-owned regular files with one hard link, without symlinks, nonempty and at most 1 MiB each. `user.key` must have no group/other permissions; mode 0600 is suitable. The certificate must not be group/world-writable. The home and `.config/craft` path must belong to the caller and not be group/world-writable. The fixed NSS home path does not follow XDG configuration overrides.

Provide an unencrypted PEM private key. Direct PFX loading, passphrase prompts, PKCS#11 and HSM backends are unsupported. CRAFT opens the files once and uses those file descriptors, so replacing a pathname does not change an identity already being loaded.

### Certificate and Identity Checks

The supplied certificate must match the key, have explicit CA:FALSE without a path length, digitalSignature usage without keyCertSign/cRLSign, and Smart Card Logon or PKINIT Client Authentication EKU. It must contain exactly one well-formed UPN otherName SAN, be currently valid for at least 60 seconds, and pass the administrator-configured CA chain and current CRLs.

Home mode does not query LDAP or compare the UPN with a directory lookup. It requests the fixed `<Linux username>@<configured realm>` principal and checks that the returned TGT is for that principal. The KDC must map the supplied certificate to that account. Alternate UPN suffixes can therefore be present in the certificate without changing the requested principal.

The enrollment template OID, all-three-EKU profile and short certificate-validity caps apply only to enrollment. Home mode accepts other templates and ordinary validity periods; a longer certificate does not lengthen the requested TGT or renewal window. `certificate_cn` does not alter a supplied certificate.

### Selection and Failure Behavior

CRAFT selects enrollment only when the home pair is absent. One missing file, unsafe ownership/permissions, symlinks, nonregular or oversized files, an encrypted or malformed key, key mismatch, invalid certificate, trust/CRL failure or PKINIT rejection fails the run and preserves the current cache. Remove both files deliberately to return to enrollment. A home-only, non-setuid installation reports that enrollment requires the setuid launcher when no pair is present.

## Access Active Directory Resources

After authentication, the user selects the resulting credential cache for an application, typically through `KRB5CCNAME`. The Kerberos library uses the cached ticket-granting ticket (TGT) to request service tickets from the domain controller for the target services. Those tickets let the application authenticate as the user to resources such as SMB file shares, LDAP directories, and Kerberos-enabled web services, where supported and configured. Access remains subject to the user's permissions and the service's policy; obtaining a ticket does not grant additional access rights.

The TGT stays in the user's cache after CRAFT exits. Applications can request service tickets while it remains valid, without another authentication or a user password prompt. Each new CRAFT run obtains a fresh TGT, reusing a supplied home pair or enrolling a fresh certificate when that pair is absent. Applications use those credentials to open service sessions.

## Certificate Storage and Cleanup

Home mode reads the user's persistent `~/.config/craft/user.pem` and `user.key`. It releases its parsed identity and sealed PKINIT memory files after authentication, while leaving the supplied files unchanged. CRAFT does not renew, overwrite or delete those certificates and keys. Users must replace the pair before expiry and protect it as a reusable authentication credential.

Enrollment generates a fresh key for each attempt. The issued certificate and key stay in process memory and temporary memory files during PKINIT; CRAFT does not save a user PEM/PFX file or certificate-store entry. The generated private key is not submitted to the CA. The CA may retain the issued certificate and audit records, including after failed or interrupted runs.

The persistent `.krb5cc_craft` cache contains the TGT and session key, without the user certificate/private key. Applications obtain service tickets from it. Renewal needs only the cache; fresh authentication uses the selected certificate workflow. Success replaces the cache, and expiry does not delete it automatically.

Enrollment-agent and transport credentials remain private under `/etc/craft`; `/run/craft` contains enrollment locks and timestamps. A home-only installation needs neither. Memory and memory files can reach swap or privileged host capture. Deleting a certificate/key, ending a process or removing a cache does not revoke KDC-issued tickets.

## Assumptions and Windows Preparation

For enrollment, the AD/PKI administrator must establish the following. Home mode needs an existing KDC-accepted certificate and the public trust/Kerberos setup described above. The Linux client does not configure Windows services. The optional [Windows provisioning helper](#windows-provisioning-helper) performs only part of this setup.

### User Identity

Provision a least-privilege directory/submission account and set its exact principal in `service_principal`. The worker looks up `sAMAccountName=<caller>` in the Active Directory Global Catalog over LDAP/GSSAPI, using the `service_principal` and `submitter.keytab` credentials. **Both CES authentication modes require these Kerberos credentials for directory lookup.** The account must have directory read access.

Set `gc_url` to a GC host whose `ldap/hostname` Kerberos SPN resolves correctly; the default is `ldap://<domain>:3268`. `gc_base_dn` defaults to the domain DN (`DC=domain,DC=local`). Pin an appropriate search base so names are unambiguous; the configured NetBIOS domain must match the account's domain. LDAP referrals are disabled. The lookup rejects zero or multiple matching entries and obtains the AD `userPrincipalName`. When the UPN attribute is absent, the fallback is `<caller>@<domain>`. Alternate UPN suffixes are retained; the Kerberos user principal remains `<caller>@<realm>`.

The signed `requestername` identifies `DOMAIN\<caller>` to the CA. The CA resolves that account and adds its SID to the issued certificate for domain-controller mapping. After enrollment, the worker checks the certificate UPN against the directory-resolved UPN. [3,6,7]

### Enrollment Agent and Dedicated Template

Use an enrollment-agent certificate with Certificate Request Agent EKU `1.3.6.1.4.1.311.20.2.1`, along with its matching private key. Constrain the enrollment agent on the CA to a dedicated template and a narrowly scoped, approved user group. Merely possessing the EKU should not confer unrestricted enrollment in your deployment. [2,3]

Provision a dedicated v2-or-later template whose issued certificate includes:

- EKUs: Smart Card Logon `1.3.6.1.4.1.311.20.2.2`, Client Authentication `1.3.6.1.5.5.7.3.2`, and PKINIT Client Authentication `1.3.6.1.5.2.3.4`. Enrollment deliberately requires all three; they are not a claim that every Windows deployment universally requires all three. [12]
- Explicit basicConstraints CA:FALSE with no path length; digitalSignature key usage; no keyCertSign/cRLSign; RSA-3072 support. The CSR also requests keyEncipherment for RSA compatibility, but the validator does not require that optional bit.
- AD-built subject/SAN for the signed requester identity, including the expected UPN. Do not enable arbitrary enrollee-supplied identity as a workaround.
- The correct CA-generated SID security extension, and the template-information extension containing the selected template OID.
- Enrollment-agent authorization/signature policy appropriate for EOBO and narrowly scoped enrollment ACLs.
- A PKI-admin-enforced short validity and compatible backdating. No hardware-key attestation, key archival, interactive approval or enrollment challenge is implemented here.

### Separate Certificate and TGT Lifetimes

The enrollment defaults accept certificates with **at most ten hours TOTAL notBefore-to-notAfter validity** and at most ten hours remaining. CA backdating consumes part of that total. Configure and independently verify the CA template/issuance policy: the CSR does not set certificate dates, and the client refuses overly long certificates rather than shortening them locally.

The program requests **36000 seconds (10 hours) of initial TGT validity and 604800 seconds (seven days / 168 hours) of renewal validity**, matching the most permissive DISA STIG guidance for Windows Server Domain Controllers (`MaxTicketAge = 10 hours`, `MaxRenewAge = 7 days`). [13,14]

**PKINIT constraint:** RFC 4556 section 3.2.3 binds initial ticket lifetime to the client key-pair lifetime, which defaults to certificate validity unless configured otherwise. The enrollment template and acceptance caps default to ten hours. Home mode accepts longer-lived certificates, while the KDC still controls initial ticket validity. This package does not establish a Windows-specific override or bypass the KDC. Validate actual behavior in your isolated lab. [12]

`require_full_tgt_lifetime=yes` makes a shorter initial grant or shortened renewable window fail without replacing an existing cache. A five-second comparison tolerance covers timestamp rounding. An administrator may set `no` to explicitly accept a shorter grant with a stderr warning. Returned times and encrypted ticket bytes are never rewritten. `craft-maintain` automates renewal and fresh authentication using the selected certificate source; `kinit -R` supports manual renewal.

### Editable Certificate Common Name

One line in `config/config.example` controls the **requested CSR CN**:

```ini
certificate_cn={user}
```

Supported substitutions are `{user}`, the directory-resolved `{upn}`, and `{domain}`; for example `certificate_cn=Linux {user}`. The expanded CN must be 1-64 printable ASCII characters. An AD-built subject template can override the request. To retain a custom CN, use an approved CA-side subject policy while preserving UPN/SID binding and enrollment-agent restrictions. Do not enable arbitrary subject/SAN supply merely to force a cosmetic CN. The CN is not the authentication identity.

### AES-Only Kerberos Profile

Initial user and transport requests offer `aes256-cts-hmac-sha1-96` (enctype 18) and `aes128-cts-hmac-sha1-96` (17), in that order. Session-key lengths and the outer TGT encryption type are checked; RC4, DES and other types are refused. The protected `krb5.conf` limits permitted enctypes and sets `ticket_lifetime = 10h` and `renew_lifetime = 7d` to match DISA STIG DC policy. Provision suitable keys/policies on the DC, krbtgt and submission account. A session key and the ticket-encryption key can have different AES sizes. [15,16]

AES is the Kerberos encryption profile, not the certificate public-key algorithm. Enrollment generates RSA-3072 keys with SHA-256 CSR/CMS signatures; a supplied key must be supported by OpenSSL and the MIT PKINIT plugin. Use a patched MIT PKINIT plugin and verify modern DH interoperability; an RSA certificate is not a request to force the obsolete RSA key-delivery mode.

The issuing CA must be trusted for smart-card logon in AD, and the chosen DC must have an appropriate PKINIT certificate and a working revocation/trust path. The Linux side also needs the relevant trust anchors and current CRLs. See Microsoft's mapping guidance and MIT's AD PKINIT configuration notes. [6,8]

### CES Transport Authentication Is Separate

An enrollment-agent signature authorizes the enrollment request; it does **not** by itself authenticate an HTTPS connection to any CES endpoint. CES supports several authentication configurations. [4]

Choose one implemented mode:

**`ces_auth=negotiate`**: use the directory submission account for HTTP Negotiate as well. The worker obtains an in-memory, five-minute transport-account TGT and requests forwardability for CES constrained delegation; this is never returned to the caller. Build against MIT Kerberos and a libcurl with GSSAPI/SPNEGO support. Require Kerberos at CES; do not configure GSS NTLM fallback. Configure the proper `HTTP/ces-host` SPN and any required constrained delegation from CES to the CA. Do not enable unrestricted client credential delegation. [4]

**`ces_auth=mtls`**: retain `service_principal` and `submitter.keytab` for LDAP, and supply separate `https-client.pem` and `https-client.key` credentials that the server maps to the authorized submitting account. Use that endpoint's actual URL. Enrollment-agent-only EKU should not be treated as sufficient TLS client authentication. The source has no username/password or SOAP UsernameToken mode. [4]

CES must allow **initial enrollment**, not be configured renewal-only. The endpoint URL in the example is a placeholder, not an autodiscovered address. A Certificate Enrollment Policy Web Service is not queried: endpoint, realm and template OID are pinned locally. Pending/approval responses are errors; there is no polling or long-running workflow.

## Build

Required: Linux with `/proc` and memfd support; setuid support is needed only for enrollment; C++20 compiler and standard library with `std::format` (GCC/libstdc++ >= 13.1 or equivalent); CMake >= 3.16; pkg-config; OpenSSL >= 3; MIT Kerberos >= 1.19; libcurl >= 7.62; libxml2 >= 2.9; OpenLDAP and Cyrus SASL development libraries; the **MIT PKINIT plugin at runtime**, plus the **Cyrus SASL GSSAPI plugin for enrollment**. Use fully patched distribution builds, not merely these minimum API versions.

CMake explicitly selects `-std=c++20`, disables GNU language extensions, and checks the required library facilities before building. A compiler accepting C++20 syntax is not enough when its standard library lacks `std::format`. GCC's implementation table lists formatting support from libstdc++ 13.1. [11]

On Debian/Ubuntu-style distributions, the usual package names are:

```sh
sudo apt-get install build-essential cmake pkg-config libssl-dev libkrb5-dev \
    krb5-user krb5-pkinit libcurl4-openssl-dev libxml2-dev \
    libldap2-dev libsasl2-dev libsasl2-modules-gssapi-mit

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Use the package names appropriate to your distribution. The SASL GSSAPI module is a separate runtime package; development headers alone do not supply it. [17] Ensure the installed `build-essential` toolchain meets the C++20 library requirement. A system with Heimdal instead of MIT Kerberos is not a supported build target. The cache serializer uses MIT's public credential-marshaling API. [9,10]

There is intentionally **no automatic setuid installation target**. Build from source on the target distribution. Never install the test program setuid.

## Install in an Isolated Lab After Reviewing the Source

Run these commands from `source/` after building. Choose a home-only installation or add the enrollment components. Public policy and trust files contain no private keys; keep them root-controlled and readable by callers.

### Home Certificate Installation

```sh
sudo install -d -o root -g root -m 0755 /usr/local/bin /usr/local/libexec /etc/craft
sudo install -o root -g root -m 0755 build/craft /usr/local/bin/craft
sudo install -o root -g root -m 0755 build/craft-worker /usr/local/libexec/craft-worker
sudo install -o root -g root -m 0755 build/craft-maintain /usr/local/bin/craft-maintain
sudo install -o root -g root -m 0644 config/krb5.conf.example /etc/craft/krb5.conf
```

Create root-owned `/etc/craft/config`, mode 0644, with the actual domain and realm. Review trust/KDC settings before enabling it:

```ini
enabled=yes
domain=domain.local
realm=DOMAIN.LOCAL
```

The default ticket policy is ten hours initial validity, seven days renewal and strict full-grant validation. Optional `tgt_seconds`, `renew_seconds` and `require_full_tgt_lifetime` apply to both workflows. Home mode does not require `netbios`, `template_oid`, `ces_url`, `ces_auth` or `service_principal`. A full enrollment configuration can also be used.

Install `ca-trust.pem`, `ca-crls.pem`, `kdc-trust.pem` and `kdc-crls.pem` under `/etc/craft`, root-owned mode 0644, and configure the actual KDC, expected hostname and PKINIT trust/revocation settings in `krb5.conf`. Include required intermediates and current issuer CRLs. All parent directories and files must be root-owned, not group/world-writable and not symlinks. Populate trust and CRL files; empty placeholders are invalid.

Provide the user pair as described above. No `craft` service account, caller group, private enrollment credentials or runtime directory is needed. The regular executable works in `nosuid` and inherited `no_new_privs` contexts, provided its public configuration and worker are accessible. Host installation and trust provisioning remain administrator tasks; certificate processing and Kerberos operations run as the caller.

### Enrollment Installation

Keep the public paths and worker from the home installation. Add the dedicated account and caller group:

```sh
sudo groupadd --system craft
sudo useradd --system --gid craft --home-dir /nonexistent \
    --shell /usr/sbin/nologin craft
sudo groupadd --system craft-users
sudo install -o root -g craft-users -m 0750 build/craft /usr/local/bin/craft
sudo install -o root -g root -m 0644 config/config.example /etc/craft/config
sudo install -o root -g root -m 0644 config/craft.tmpfiles.conf /etc/tmpfiles.d/craft.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/craft.conf
```

On non-systemd hosts, create `/run/craft` owned `craft:craft`, mode 0700, at each boot. Never add ordinary callers to the `craft` service group. Membership in `craft-users` permits execution of the restricted launcher; it does not grant access to enrollment keys.

### Required Files

| File under `/etc/craft` | Workflow and purpose | Ownership and mode |
| --- | --- | --- |
| `config` | Both: enabled flag, domain/realm and ticket policy; enrollment adds template, CES/GC settings and service principal | `root:root`, 0644 |
| `krb5.conf` | Both: pinned realm/KDC, hostname, PKINIT trust and revocation policy | `root:root`, 0644 |
| `ca-trust.pem`, `ca-crls.pem` | Both: certificate CA chain and current issuer CRLs | `root:root`, 0644 |
| `kdc-trust.pem`, `kdc-crls.pem` | Both: KDC trust chain and current CRLs | `root:root`, 0644 |
| `agent.pem`, `agent.key` | Enrollment: agent certificate and matching unencrypted private key | `root:craft`, 0640 |
| `submitter.keytab` | Enrollment: directory/submission account for both CES authentication modes | `root:craft`, 0640 |
| `https-trust.pem` | Enrollment: CES HTTPS trust chain | `root:craft`, 0640 |
| `https-client.pem`, `https-client.key` | Enrollment with mTLS: separate HTTPS client identity | `root:craft`, 0640 |

Protect original PFX exports and the extraction process. Keep private keys and keytabs inaccessible to callers. Configure administrator-controlled CRL refresh; CRAFT does not follow arbitrary AIA/CRL locations. Additional trusted roots expand the accepted issuer set.

Complete the CA, template, transport and recipient restrictions; replace all example values. Then enable a test user and the privileged enrollment entry point:

```sh
sudo usermod -aG craft-users alice
# Review /etc/craft/config and set enabled=yes.
sudo chmod 4750 /usr/local/bin/craft
```

A new login is normally needed for group changes. Invoke directly as the intended user, without `sudo craft`. Enrollment needs setuid elevation; `nosuid` or inherited `no_new_privs` prevents that fallback. A present home pair still uses the caller workflow without elevation. [1]

## Use

To select the resulting cache in the current shell, preserving error status:

```sh
cache=$(/usr/local/bin/craft) && export KRB5CCNAME="$cache" && \
    klist -ef -c "$KRB5CCNAME"
```

For a script, stop when credential acquisition fails:

```sh
#!/bin/sh
set -eu
cache=$(/usr/local/bin/craft)
export KRB5CCNAME="$cache"
klist -c "$KRB5CCNAME"
# Run the Kerberos-enabled Application Here.
```

The optional ordinary wrapper `scripts/with-craft` runs any command with the new cache selected:

```sh
./scripts/with-craft klist
```

The executable cannot modify a parent shell's environment. The cache belongs to the caller and contains that caller's TGT and session key. Treat it as a sensitive credential; exclude it from backups, sync and indexing where practicable. Existing content at the fixed cache name is intentionally replaced only after successful certificate validation, PKINIT and file publication. Nothing automatically removes an expired cache.

### Long-running jobs

Start once from the batch script as the approved user:

```sh
job_pid=$$
cache=$(/usr/local/bin/craft-maintain --watch-pid "$job_pid") || exit "$?"
export KRB5CCNAME="$cache"
```

The command returns when usable credentials and detached maintenance are ready. It renews TGTs from the cache alone and obtains fresh credentials near the absolute renewal deadline. Ten-hour/seven-day grants normally renew at eight hours and authenticate afresh around day six; actual ticket times set the schedule. Fresh acquisition invokes `craft` and follows the home-pair priority. It reuses a valid supplied pair and enrolls only when neither file is present. Replace a home certificate before expiry; maintenance does not renew that certificate.

Install `craft-maintain` without setuid/setgid on Linux 5.3+ with `/proc`. Configure administrator-controlled system `/etc/krb5.conf` for the same realm, KDC and AES policy as `/etc/craft/krb5.conf`. Renewal ignores user Kerberos overrides. The scheduler must retain background processes in the job cgroup. Home-only refresh works under `no_new_privs`; enrollment fallback additionally requires later setuid `craft` calls.

The watched PID must belong to the caller and last for the job: keep its shell alive, `exec` the job or watch its controller. Maintenance stops with that PID; optional `--max-duration 21d` adds a cutoff. Jobs for one UID coordinate the shared cache, which remains after maintenance stops. Applications must reload refreshed credentials when authenticating again.

Inspect as the same user, using the original watched PID:

```sh
/usr/local/bin/craft-maintain --status --watch-pid "$job_pid"
klist -ef -c "$KRB5CCNAME"
```

Status reports `ready`, `retrying`, `expired`, `stopped` or `failed`, Unix ticket times and the last error; `next_check=0` means stopped. A successful read does not prove credential health. Private status files remain after exit; events use the `craft-maintain` AUTHPRIV log identity.

Renewal failures preserve the cache and retry without immediate fresh authentication. Missing/expired TGTs, tickets that cannot extend near expiry and renewal-window rollover require fresh credentials. Failed fresh acquisitions share a cooldown from one minute to one hour, including home-certificate failures. Startup requires a usable TGT; later failures appear in status/logs and do not stop the job. Keep CRLs, the selected certificate credentials and KDC connectivity current.

## Limits and Failure Behavior

Both paths reject runtime UID/name mismatches, key mismatch, missing logon usage, untrusted/revoked chains, missing or expired required CRLs, invalid certificate dates and unexpected TGT principals, flags, encryption or lifetimes. Password prompts and user-password/keytab fallback are refused. Home mode also rejects incomplete or unsafe files and delegates certificate-to-account mapping to the KDC. Enrollment additionally rejects unknown/ambiguous AD users, wrong UPN/template, excessive certificate validity, SOAP faults and pending/unsupported responses.

Enrollment has one issuance in flight per UID and a default 60-second interval between attempts, including failures; its locks and timestamps reside under `/run/craft`. Home mode has no enrollment interval or runtime-directory dependency. Maintainer retry/cooldown rules still apply to fresh acquisition failures in either mode.

Only validated credentials replace the cache. The writer runs as the caller, requires a caller-owned home that is not group/world-writable, stages a unique mode-0600 file and atomically replaces the fixed name without following a target symlink. Final-component home symlinks are refused. Assess network-home access controls separately.

Enrollment certificate caps accept 60 to 86400 seconds, with remaining validity no greater than total validity; both default to 36000. They do not cap supplied home certificates. Ticket requests are independently configured, defaulting to 36000 seconds initial validity and 604800 seconds renewal; parser maxima are 604800 for each. Actual grants must satisfy configured limits and strict/full-grant policy. The KDC can cap initial PKINIT validity by certificate/key lifetime. Keep clocks synchronized.

Enrollment timeouts can leave a CA-issued certificate recorded after its generated key is discarded. CRAFT does not cancel issuance or revoke certificates. The enrollment service account remains sensitive because it can read the agent and transport credentials; a home-only deployment removes that enrollment authority from the host. A supplied persistent private key and the ticket cache remain reusable credentials that require protection.

See [SECURITY.md](SECURITY.md) and [TESTING.md](TESTING.md) before deployment. The Word guides are in [docs](../docs/).

## Request a Home Certificate on Windows

[`Request-CRAFT-Certificate.cmd`](../scripts/Request-CRAFT-Certificate.cmd) is a CMD/Windows PowerShell 5.x polyglot that requests a certificate as the signed-in domain user and exports the home PEM pair. Run it without elevation on a Windows computer that can reach AD and its enterprise CA enrollment endpoints. Windows PowerShell 5.x, .NET Framework 4.6 or newer, and the Windows PKI module are required; RSAT and OpenSSL are unnecessary.

Choose a template's internal name or OID that permits this user's direct enrollment and exportable RSA or ECDSA software keys. Its certificate profile must meet the [home certificate requirements](#home-certificate-workflow) and the KDC's mapping policy. The Windows account must map to the intended Linux username and realm. Windows [AD enrollment policy](https://learn.microsoft.com/en-us/powershell/module/pki/get-certificate) selects an eligible CA; no CA name, enrollment agent or administrator credential is supplied.

From the repository root in either CMD or PowerShell, use a dedicated local destination directory:

```bat
.\scripts\Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate"
.\scripts\Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate" /WhatIf
.\scripts\Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate" /DeleteAfterExport
```

The helper writes a PEM certificate `user.pem`, matching unencrypted PKCS#8 private key `user.key`, and private `.craft-certificate.json` tracking metadata. Keep the metadata in the Windows destination for repeat runs; only the PEM pair is needed on Linux. New directories and files allow only the caller, SYSTEM and local administrators. Incomplete, modified, unmanaged or different-template output is refused before enrollment. The export uses an encrypted PFX only in memory and does not require a PFX file on disk.

The default renewal window is one calendar month before the recorded certificate's expiration. On each invocation, reuse the pair outside that window; otherwise obtain a new certificate and key. `/RenewBeforeDays N` overrides the default with a window from 0 to 3650 days, including fractional days; 0 replaces only expired certificates. Stage the replacement before publishing it, restore the old exports on publication failure, and retain the old Windows credential on pending, denied or failed enrollment/export. Successful renewal replaces the managed files and removes the old certificate from `Cert:\CurrentUser\My`.

`/DeleteAfterExport` is optional and defaults off. Enable it to remove the current Windows-store certificate after a successful export or reuse; the PEM files remain. Associated Windows private keys are deleted only when no other certificate in that user's My store shares the public key. Removal is local and does not revoke certificates or issued tickets. A store-cleanup error returns failure while preserving the usable exports for inspection.

Exit status is 0 for a successful export, reuse or preview, 1 for failure, 2 for pending CA approval, and 64 for invalid CMD arguments. A pending request remains in the Windows request store and leaves existing exports in place. Use Windows enrollment tools to retrieve approved requests. Failed enrollment/export retains Windows credentials.

Transfer both files securely to the Linux user, install them at `~/.config/craft/user.pem` and `user.key` with private permissions as described in [home certificate installation](#home-certificate-installation), and remove unneeded transfer copies. Provision the issuing trust chain and current CRLs under `/etc/craft` separately. CRAFT validates the pair and obtains the TGT as the caller. The Windows helper checks renewal only when invoked; schedule repeat runs separately and transfer replacements before expiry. Certificate renewal is independent of TGT maintenance.

## Windows Provisioning Helper

[`scripts/Configure-CRAFT-CA.ps1`](../scripts/Configure-CRAFT-CA.ps1) is an optional lab helper that changes AD accounts, certificate templates and CA publication, exports credentials, and writes disabled Linux configuration. Read its source before running it as an administrator. From the repository root, inspect parameter help:

```powershell
Get-Help .\scripts\Configure-CRAFT-CA.ps1 -Full
```

The helper provisions the enrollment workflow; it is not required for a home-only installation. Supply the required `CesUrl`, `AllowedTargetGroup` and `ExportPassword` parameters. Review the selected CA and DC, target group, password handling and exported credentials. An existing `submitter.keytab` stops the helper before changes; plan credential rotation separately. Automatic enrollment-agent certificate export requires running as `EnrollmentAgentIdentity`; otherwise provision `agent.pfx` for that signing identity separately. The helper uses the same named account for the keytab and signing certificate; provision separate accounts manually when your deployment requires them. It does not complete CES installation, HTTP SPNs/delegation, CA enrollment-agent restrictions, or the Linux installation. Complete the CA's **Enrollment Agents** restrictions for the actual signing certificate identity, chosen template and approved recipient group. Verify the issued certificate's total lifetime, including CA backdating. Provision any missing chain certificates and CRLs and convert DER/PFX exports to the PEM files listed above. Review the configuration before setting `enabled=yes` for an approved lab user.

## Primary References

1. [Linux `execve(2)`, script/setuid and `no_new_privs` behavior](https://man7.org/linux/man-pages/man2/execve.2.html)
2. [Microsoft MS-WCCE, PKCS#7 processing for EOBO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/05726113-2d51-4030-a568-4fb812d7ee6a)
3. [Microsoft MS-WCCE, enrollment name/value attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/92f07a54-2889-45e3-afd0-94b60daa80ec)
4. [Microsoft, configuring CES](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-certificate-enrollment-web-service)
5. [Microsoft MS-WSTEP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/4766a85d-0d18-4fa1-a51f-e5cb98b752ea)
6. [Microsoft KB5014754, strong certificate mapping](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)
7. [Microsoft MS-WCCE, SID extension](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e563cff8-1af6-4e6f-a655-7571ca482e71)
8. [MIT Kerberos, PKINIT configuration](https://web.mit.edu/kerberos/krb5-current/doc/admin/pkinit.html)
9. [MIT Kerberos, credential marshaling](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_marshal_credentials.html)
10. [MIT Kerberos, FILE cache format](https://web.mit.edu/kerberos/krb5-current/doc/formats/ccache_file_format.html)
11. [GCC/libstdc++ C++20 implementation status](https://gcc.gnu.org/onlinedocs/libstdc++/manual/status.html#status.iso.2020)
12. [RFC 4556, client usage and key/ticket lifetime](https://datatracker.ietf.org/doc/html/rfc4556#section-3.2.3)
13. [Microsoft, Maximum lifetime for user ticket](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-lifetime-for-user-ticket)
14. [Microsoft, Maximum lifetime for user ticket renewal](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj852196(v=ws.11))
15. [MIT, initial-credential enctype list](https://web.mit.edu/kerberos/krb5-latest/doc/appdev/refs/api/krb5_get_init_creds_opt_set_etype_list.html)
16. [MIT, krb5.conf](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html)
17. [Debian, MIT GSSAPI SASL runtime module](https://packages.debian.org/trixie/libsasl2-modules-gssapi-mit)

The included implementation is not a Microsoft-supported Linux enrollment client. These references do not endorse this code.

## License

CRAFT source code, scripts, configuration examples, and documentation are licensed under the GNU General Public License, version 3 (SPDX: `GPL-3.0-only`). See [LICENSE](../LICENSE) for the full terms. This material is provided without warranty, as described in the license.
