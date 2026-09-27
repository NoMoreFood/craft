# CRAFT - Certificate Request Agent for Tickets

CRAFT obtains Kerberos credentials on behalf of an approved user, noninteractively, from a trusted and administrator-managed Linux endpoint. It supports unattended scripts and Kerberos-aware applications that need to access Active Directory resources as that user, even when the Linux host is not domain-joined. A short-lived certificate provides the authentication path, so automation does not need to collect, store, or replay the user's AD password.

This is useful where interactive sign-in is protected by two-factor or multifactor authentication and retaining a reusable user password for automation would undermine that approach. Administrators explicitly authorize a separate certificate-enrollment path for selected users and trusted hosts. CRAFT does not perform an MFA challenge or establish that the user has completed one; its authority comes from the managed endpoint, enrollment credentials, and CA restrictions.

C++20 | DISA STIG Kerberos defaults (10h TGT, 7d renewal) | 10h certificate cap | AES256/AES128.

**Deployment model:** Use `craft`, `craft-worker`, `/etc/craft`, the `craft` service account, and the `craft-users` caller group. The cache is written to `.krb5cc_craft` in the caller's home directory.

**Status:** Reference implementation with synthetic offline tests. Live AD/CES/PKINIT interoperability and the installed privilege boundary require an isolated lab trial before production use.

This project supplies native C++20 Linux executables for a host that cannot join an AD domain. It requests a real user TGT through an actual domain controller. It does not forge tickets, use domain ticket-signing secrets, or substitute a service-account TGT for the user's TGT.

It creates a temporary **software-backed certificate with Smart Card Logon usage**, not a Windows TPM-backed virtual smart card. No hardware possession, PIN, attestation, or MFA claim is established by this implementation.

## Process and Access Boundaries

The no-argument launcher checks the caller and starts certificate and ticket processing under a dedicated service account. CRAFT validates the directory identity, issued certificate, and returned ticket before publishing a cache owned by the caller. Administrator-provisioned enrollment credentials remain separate from the user ticket cache.

## What Happens

1. An authorized user invokes `/usr/local/bin/craft`, a small, compiled setuid-root launcher with **no arguments**. Linux ignores setuid bits on interpreter scripts; an ordinary script can call this binary. [1]
2. The launcher identifies the real calling UID, resolves its NSS/passwd name and home, and verifies the runtime calling account with a runtime UID/NSS check. It ignores `$USER`, `$HOME`, `SUDO_USER`, and user Kerberos configuration.
3. It starts a fixed worker executable, permanently drops the worker to the dedicated `craft` Unix account, and permanently drops the cache-writing parent back to the caller. Certificate, XML, TLS and Kerberos processing do not run as root.
4. The worker generates a fresh RSA-3072 key and PKCS#10 request. Its UPN SAN is an `otherName` with OID `1.3.6.1.4.1.311.20.2.3`, containing the directory-resolved UPN as a UTF8String.
5. It wraps the CSR in CMS SignedData, signed using the enrollment-agent certificate and private key. A signed Microsoft `requestername` attribute identifies `DOMAIN\linuxname`. This is enrollment on behalf of another user, not signing the final user certificate locally. [2,3]
6. It submits that request to **AD CS Certificate Enrollment Web Service (CES)** using MS-WSTEP over verified HTTPS. It implements neither legacy `/certsrv` page scraping nor a Linux DCOM/RPC client. [4,5]
7. The returned certificate must have the expected key, UPN, CA-generated AD SID, template OID, usage and short validity, and pass trust-chain/CRL checks. A UPN alone is not enough for current Windows certificate mapping; this implementation requires the SID extension rather than weakening domain-controller policy. [6,7]
8. MIT Kerberos performs PKINIT using the issued certificate/key through sealed Linux memory-file descriptors. A 10-hour non-forwardable, non-proxiable TGT with 7-day renewal is requested, and returned flags, identity and expiry are checked. [8]
9. The caller-side process writes a mode-0600 FILE credential cache to the caller's actual home using an atomic rename. The fixed filename is `.krb5cc_craft`. It prints the resulting `FILE:/absolute/path/.krb5cc_craft` cache name, not credentials.

## Access Active Directory Resources

After enrollment and authentication, the user selects the resulting credential cache for an application, typically through `KRB5CCNAME`. The Kerberos library uses the cached ticket-granting ticket (TGT) to request service tickets from the domain controller for the target services. Those tickets let the application authenticate as the user to resources such as SMB file shares, LDAP directories, and Kerberos-enabled web services, where supported and configured. Access remains subject to the user's permissions and the service's policy; obtaining a ticket does not grant additional access rights.

The TGT stays in the user's cache after CRAFT exits. Applications can request service tickets while it remains valid, without another enrollment or a user password prompt. Each new CRAFT run obtains a fresh certificate and TGT; it does not itself connect to file shares, query LDAP, or open application sessions.

## Certificate Storage and Cleanup

Each enrollment attempt generates a fresh user private key. The issued certificate and key stay in process memory and temporary memory-backed files during PKINIT. CRAFT does not save them as persistent PEM/PFX files, install them in a certificate store, or place them in the caller's home, `/etc/craft`, `/run/craft`, or a temporary directory. The temporary files close after authentication, and the worker releases its certificate and key when it exits. The user private key is generated locally and is not submitted to the CA.

The persistent user credential is `.krb5cc_craft` in the caller's actual home. It contains the Kerberos TGT and session key, not the issued certificate or private key. Applications use the cache to obtain service tickets, and eligible TGT renewal uses the cache without the discarded certificate/key. CRAFT has no background renewal service and does not remove an expired cache automatically. A new successful run replaces the cache using a fresh enrollment.

Administrator-provisioned enrollment-agent and transport credentials remain under `/etc/craft`; they are separate from the temporary user identity. `/run/craft` holds per-user lock and timing information. The CA may retain the issued public certificate, request, and audit records even after a failed run; CRAFT does not automatically cancel issuance or revoke it.

Ephemeral means no persistent user certificate/key file is intentionally created on the client. Process and memory-file contents can still reach swap or be exposed through host memory capture or privileged access. Client cleanup neither erases CA records nor invalidates a ticket already issued by the domain controller.

## Assumptions and Windows Preparation

The AD/PKI administrator must establish the following. The Linux client does not configure Windows services. The optional [Windows provisioning helper](#windows-provisioning-helper) performs only part of this setup.

### User Identity

Provision a least-privilege directory/submission account and set its exact principal in `service_principal`. The worker looks up `sAMAccountName=<caller>` in the Active Directory Global Catalog over LDAP/GSSAPI, using the `service_principal` and `submitter.keytab` credentials. **Both CES authentication modes require these Kerberos credentials for directory lookup.** The account must have directory read access.

Set `gc_url` to a GC host whose `ldap/hostname` Kerberos SPN resolves correctly; the default is `ldap://<domain>:3268`. `gc_base_dn` defaults to the domain DN (`DC=domain,DC=local`). Pin an appropriate search base so names are unambiguous; the configured NetBIOS domain must match the account's domain. LDAP referrals are disabled. The lookup rejects zero or multiple matching entries and obtains the AD `objectSid` and `userPrincipalName`. When the UPN attribute is absent, the fallback is `<caller>@<domain>`. Alternate UPN suffixes are retained; the Kerberos user principal remains `<caller>@<realm>`.

The CA, not this client, adds that user's SID to the issued certificate. The code never inserts a chosen SID into its CSR. After enrollment, the worker validates that the certificate issued by the CA matches the exact identity, UPN, and SID retrieved from Active Directory. [7]

### Enrollment Agent and Dedicated Template

Use an enrollment-agent certificate with Certificate Request Agent EKU `1.3.6.1.4.1.311.20.2.1`, along with its matching private key. Constrain the enrollment agent on the CA to a dedicated template and a narrowly scoped, approved user group. Merely possessing the EKU should not confer unrestricted enrollment in your deployment. [2,3]

Provision a dedicated v2-or-later template whose issued certificate includes:

- EKUs: Smart Card Logon `1.3.6.1.4.1.311.20.2.2`, Client Authentication `1.3.6.1.5.5.7.3.2`, and PKINIT Client Authentication `1.3.6.1.5.2.3.4`. This application deliberately requires all three; they are not a claim that every Windows deployment universally requires all three. [12]
- Explicit basicConstraints CA:FALSE with no path length; digitalSignature key usage; no keyCertSign/cRLSign; RSA-3072 support. The CSR also requests keyEncipherment for RSA compatibility, but the validator does not require that optional bit.
- AD-built subject/SAN for the signed requester identity, including the expected UPN. Do not enable arbitrary enrollee-supplied identity as a workaround.
- The correct CA-generated SID security extension, and the template-information extension containing the selected template OID.
- Enrollment-agent authorization/signature policy appropriate for EOBO and narrowly scoped enrollment ACLs.
- A PKI-admin-enforced short validity and compatible backdating. No hardware-key attestation, key archival, interactive approval or enrollment challenge is implemented here.

### Separate Certificate and TGT Lifetimes

The defaults accept certificates with **at most ten hours TOTAL notBefore-to-notAfter validity** and at most ten hours remaining. CA backdating consumes part of that total. Configure and independently verify the CA template/issuance policy: the CSR does not set certificate dates, and the client refuses overly long certificates rather than shortening them locally.

The program requests **36000 seconds (10 hours) of initial TGT validity and 604800 seconds (seven days / 168 hours) of renewal validity**, matching the most permissive DISA STIG guidance for Windows Server Domain Controllers (`MaxTicketAge = 10 hours`, `MaxRenewAge = 7 days`). [13,14]

**PKINIT constraint:** RFC 4556 section 3.2.3 binds initial ticket lifetime to the client key-pair lifetime, which defaults to certificate validity unless configured otherwise. Thus, the client certificate template validity and acceptance caps are set to 10 hours to permit the full 10-hour initial grant. This package does not establish a Windows-specific override or bypass the KDC. Validate actual behavior in your isolated lab. [12]

`require_full_tgt_lifetime=yes` makes a shorter initial grant or shortened renewable window fail without replacing an existing cache. A five-second comparison tolerance covers timestamp rounding. An administrator may set `no` to explicitly accept a shorter grant with a stderr warning. Returned times and encrypted ticket bytes are never rewritten. There is no automatic renewal or re-enrollment daemon; user tickets may be renewed up to the 7-day limit using standard Kerberos tools (e.g., `kinit -R`).

### Editable Certificate Common Name

One line in `config/config.example` controls the **requested CSR CN**:

```ini
certificate_cn={user}
```

Supported substitutions are `{user}`, the directory-resolved `{upn}`, and `{domain}`; for example `certificate_cn=Linux {user}`. The expanded CN must be 1-64 printable ASCII characters. An AD-built subject template can override the request. To retain a custom CN, use an approved CA-side subject policy while preserving UPN/SID binding and enrollment-agent restrictions. Do not enable arbitrary subject/SAN supply merely to force a cosmetic CN. The CN is not the authentication identity.

### AES-Only Kerberos Profile

Initial user and transport requests offer `aes256-cts-hmac-sha1-96` (enctype 18) and `aes128-cts-hmac-sha1-96` (17), in that order. Session-key lengths and the outer TGT encryption type are checked; RC4, DES and other types are refused. The protected `krb5.conf` limits permitted enctypes and sets `ticket_lifetime = 10h` and `renew_lifetime = 7d` to match DISA STIG DC policy. Provision suitable keys/policies on the DC, krbtgt and submission account. A session key and the ticket-encryption key can have different AES sizes. [15,16]

AES is the Kerberos encryption profile, not the certificate public-key algorithm: user certificates retain RSA-3072 keys with SHA-256 CSR/CMS signatures. Use a patched MIT PKINIT plugin and verify modern DH interoperability; an RSA certificate is not a request to force the obsolete RSA key-delivery mode.

The issuing CA must be trusted for smart-card logon in AD, and the chosen DC must have an appropriate PKINIT certificate and a working revocation/trust path. The Linux side also needs the relevant trust anchors and current CRLs. See Microsoft's mapping guidance and MIT's AD PKINIT configuration notes. [6,8]

### CES Transport Authentication Is Separate

An enrollment-agent signature authorizes the enrollment request; it does **not** by itself authenticate an HTTPS connection to any CES endpoint. CES supports several authentication configurations. [4]

Choose one implemented mode:

**`ces_auth=negotiate`**: use the directory submission account for HTTP Negotiate as well. The worker obtains an in-memory, five-minute transport-account TGT and requests forwardability for CES constrained delegation; this is never returned to the caller. Build against MIT Kerberos and a libcurl with GSSAPI/SPNEGO support. Require Kerberos at CES; do not configure GSS NTLM fallback. Configure the proper `HTTP/ces-host` SPN and any required constrained delegation from CES to the CA. Do not enable unrestricted client credential delegation. [4]

**`ces_auth=mtls`**: retain `service_principal` and `submitter.keytab` for LDAP, and supply separate `https-client.pem` and `https-client.key` credentials that the server maps to the authorized submitting account. Use that endpoint's actual URL. Enrollment-agent-only EKU should not be treated as sufficient TLS client authentication. The source has no username/password or SOAP UsernameToken mode. [4]

CES must allow **initial enrollment**, not be configured renewal-only. The endpoint URL in the example is a placeholder, not an autodiscovered address. A Certificate Enrollment Policy Web Service is not queried: endpoint, realm and template OID are pinned locally. Pending/approval responses are errors; there is no polling or long-running workflow.

## Build

Required: Linux with `/proc`, memfd and setuid support; C++20 compiler and standard library with `std::format` (GCC/libstdc++ >= 13.1 or equivalent); CMake >= 3.16; pkg-config; OpenSSL >= 3; MIT Kerberos >= 1.19; libcurl >= 7.62; libxml2 >= 2.9; OpenLDAP and Cyrus SASL development libraries; the **MIT PKINIT and Cyrus SASL GSSAPI plugins at runtime**. Use fully patched distribution builds, not merely these minimum API versions.

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

Run these commands from the source directory. Create the named system accounts/groups only once; adapt to your local account-management tooling.

```sh
sudo groupadd --system craft
sudo useradd --system --gid craft --home-dir /nonexistent \
    --shell /usr/sbin/nologin craft
sudo groupadd --system craft-users

sudo install -d -o root -g root -m 0755 /usr/local/bin /usr/local/libexec
sudo install -d -o root -g craft -m 0750 /etc/craft
sudo install -o root -g craft -m 0750 \
    build/craft-worker /usr/local/libexec/craft-worker
sudo install -o root -g craft-users -m 0750 \
    build/craft /usr/local/bin/craft

sudo install -o root -g craft -m 0640 \
    config/config.example /etc/craft/config
sudo install -o root -g craft -m 0640 \
    config/krb5.conf.example /etc/craft/krb5.conf

sudo install -o root -g root -m 0644 \
    config/craft.tmpfiles.conf /etc/tmpfiles.d/craft.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/craft.conf
```

On a non-systemd system, create `/run/craft` owned `craft:craft`, mode `0700`, at each boot. Never put ordinary users in the `craft` service group. Only authorized callers belong in `craft-users`.

### Required Files

Install the following administrator-provisioned files under `/etc/craft`, all root-owned, group `craft`, mode `0640`:

| File | Purpose |
| --- | --- |
| `config` | Domain/realm, template OID, CES/GC endpoints, service principal and limits; shipped disabled. |
| `krb5.conf` | Pinned DC, realm, PKINIT trust, expected KDC hostname and revocation policy. |
| `agent.pem` | Enrollment-agent leaf certificate, PEM. |
| `agent.key` | Matching unencrypted PEM private key; access limited to root/service account. |
| `ca-trust.pem` | PEM CA chain/trust needed to validate both enrollment agent and user logon certificates; include required intermediates. |
| `ca-crls.pem` | Current PEM CRLs for those chains, including intermediate-CA issuers as needed. |
| `kdc-trust.pem` | PKINIT KDC trust anchors, PEM. |
| `kdc-crls.pem` | Current PEM CRLs for the KDC chain. |
| `https-trust.pem` | PEM trust anchors/chain for the CES HTTPS certificate. |
| `submitter.keytab` | Required in both modes for the directory/submission account. |
| `https-client.pem`, `https-client.key` | Required only for `mtls`; separate HTTPS-client identity. |

PEM private keys must be readable noninteractively; direct PFX loading, passphrase prompts, PKCS#11 and HSM access are not implemented. Protect the original PFX and its extraction process separately. Trust/CRL files must be populated, not empty placeholder files. Configure automated **administrator-controlled** CRL refresh; the program deliberately does not follow arbitrary AIA/CRL network locations.

Files under `/etc/craft` and their parent directories must be root-owned, not group/world-writable, and not symlinks. The caller home and private `/run/craft` runtime directory follow their separate ownership rules. CA certificate files can be shared between purposes only after deliberate trust review. Trusting additional roots expands the accepted issuer set.

Edit all example values, provision credentials, and arrange CA-side restrictions. Then enable only a test user:

```sh
sudo usermod -aG craft-users alice
# Edit /etc/craft/config; set enabled=yes Only After Configuration Review.
# Final Explicit Privileged-install Step, for Lab Validation:
sudo chmod 4750 /usr/local/bin/craft
```

A new login is normally needed for group membership to take effect. Invoke directly as the intended user, **not** through `sudo craft`; the latter changes the real UID and is rejected. A `nosuid` mount or no-new-privileges execution context prevents the elevation and the launcher rejects the call. [1]

## Use

To select the resulting cache in the current shell, preserving error status:

```sh
cache=$(/usr/local/bin/craft) && export KRB5CCNAME="$cache" && \
    klist -ef -c "$KRB5CCNAME"
```

For a script, stop when enrollment fails:

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

The executable cannot modify a parent shell's environment. The cache belongs to the caller and contains that caller's TGT and session key. Treat it as a sensitive credential; exclude it from backups, sync and indexing where practicable. Existing content at the fixed cache name is intentionally replaced only after successful enrollment/PKINIT and file publication. Nothing automatically removes an expired cache.

## Limits and Failure Behavior

The worker rejects unknown Active Directory accounts, runtime UID/name mismatches, mismatched identities/keys/templates, missing SID/EKUs, untrusted or revoked chains, missing/expired required CRLs, excessive certificate validity, unexpected TGT principals/flags/expiry, SOAP faults and unsupported/pending responses. It refuses password prompts and supplies no user password/keytab fallback.

Each UID has one issuance in flight and a default 60-second interval between attempts, including failed attempts. Locks/timestamps reside in the private runtime directory. Timeouts can leave an already-issued certificate in the CA database whose private key has been discarded; there is no automatic CA-side cancellation or revocation. Establish CA cleanup/audit policy and capacity planning separately.

The cache-writing process has already dropped to the caller before opening the home directory. It requires a caller-owned, non-group/world-writable home; creates a unique mode-0600 temporary file; and atomically replaces the fixed name without following an existing target symlink. A final-component symlink home is refused. Network homes and their actual access controls need separate assessment.

The configuration accepts certificate caps from 60 to 86400 seconds, with remaining validity no greater than total validity; both default to 36000 (10 hours). Raising them changes the certificate acceptance policy. The code allows a requested user-ticket lifetime up to 10 hours and renewal lifetime up to seven days, checking the actual granted duration and flags with a five-second tolerance. The DC may cap a PKINIT grant to the certificate/key lifetime. Keep clocks closely synchronized. The separate CES transport account still requests a five-minute TGT; that credential is not returned to the caller.

The service account has access to enrollment credentials and is therefore security-sensitive even though it is not root. A compromised service account or host root can abuse the identities permitted by CA policy. This helper is not a substitute for a remote, separately protected authorization service.

See [SECURITY.md](SECURITY.md) and [TESTING.md](TESTING.md) before deployment. The concise Word guides are in [docs](../docs/).

## Windows Provisioning Helper

[`scripts/Configure-CRAFT-CA.ps1`](../scripts/Configure-CRAFT-CA.ps1) is an optional lab helper that changes AD accounts, certificate templates and CA publication, exports credentials, and writes disabled Linux configuration. Read its source before running it as an administrator. From the repository root, inspect parameter help:

```powershell
Get-Help .\scripts\Configure-CRAFT-CA.ps1 -Full
```

Supply the required `CesUrl`, `AllowedTargetGroup` and `ExportPassword` parameters. Review the selected CA and DC, target group, password handling and exported credentials. An existing `submitter.keytab` stops the helper before changes; plan credential rotation separately. Automatic enrollment-agent certificate export requires running as `EnrollmentAgentIdentity`; otherwise provision `agent.pfx` for that signing identity separately. The helper uses the same named account for the keytab and signing certificate; provision separate accounts manually when your deployment requires them. It does not complete CES installation, HTTP SPNs/delegation, CA enrollment-agent restrictions, or the Linux installation. Complete the CA's **Enrollment Agents** restrictions for the actual signing certificate identity, chosen template and approved recipient group. Verify the issued certificate's total lifetime, including CA backdating. Provision any missing chain certificates and CRLs and convert DER/PFX exports to the PEM files listed above. Review the configuration before setting `enabled=yes` for an approved lab user.

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
