# CRAFT: Certificate Request Agent for Tickets

CRAFT obtains a user's Kerberos ticket-granting ticket (TGT) through PKINIT from Linux, including hosts that are not domain-joined. It supports **three operating modes**: privileged certificate enrollment, privileged credential linking, and unprivileged authentication with a certificate exported from Windows. All three publish the user's ticket cache for unattended scripts and Kerberos-aware applications without storing the user's AD password.

## Choose an operating mode

| Mode | How Linux obtains the PKINIT identity | Linux installation | Setup instructions |
| --- | --- | --- | --- |
| **1. Privileged certificate enrollment** | CRAFT generates a key and enrolls a short-lived user certificate through AD CS CES using an enrollment agent. | Setuid launcher and dedicated service account; `mechanism=enrollment` | [Enrollment setup](source/README.md#mode-1-setup-privileged-certificate-enrollment) |
| **2. Privileged credential linking (Key Trust)** | CRAFT generates a temporary key, adds its public key to the user's AD `msDS-KeyCredentialLink`, performs PKINIT, and removes the entry. | Setuid launcher and dedicated service account; `mechanism=key_trust` | [Credential-linking setup](source/README.md#mode-2-setup-privileged-credential-linking) |
| **3. Unprivileged Windows-exported certificate** | The user enrolls and exports a certificate and private key on Windows, transfers the PEM pair to Linux, and CRAFT uses it for PKINIT. | Ordinary executables; acquisition runs as the caller | [Windows export and Linux setup](source/README.md#mode-3-setup-unprivileged-windows-exported-certificate) |

“Privileged” describes the Linux installation's authority to act on behalf of approved users. Users invoke `craft` directly as themselves, without `sudo`. The setuid launcher starts the privileged-mode worker under the dedicated `craft` service account; certificate, LDAP, CES and Kerberos processing run outside root. Cache publication runs as the caller.

**Selection is automatic:** a complete `~/.config/craft/user.pem` and `user.key` pair takes priority on every installation. Only when both files are absent does `mechanism` select mode 1 or 2. Partial, unsafe or invalid files fail and preserve the existing cache. CRAFT does not switch between enrollment and credential linking after a failure. An ordinary installation needs a valid PEM pair and cannot use either privileged mode.

All modes request `<Linux username>@<configured realm>`. The KDC authenticates the certificate or linked key, decides the ticket grant, and enforces account mapping. CRAFT validates the returned TGT before atomically publishing a caller-owned mode-0600 `.krb5cc_craft` in the NSS-resolved home directory.

All modes need administrator-controlled Linux Kerberos configuration, KDC trust and current CRLs. Modes 1 and 3 also validate the user certificate against configured CA trust and CRLs. Mode 2 authenticates the user through the linked public key and still validates the KDC certificate.

![CRAFT selects the supplied home pair first, then the configured privileged mechanism only when both files are absent.](output/pdf/svg/01-system-overview.svg)

## Mode 1: Privileged certificate enrollment

Linux orchestrates directory lookup, fresh RSA key generation, an enrollment-on-behalf-of (EOBO) request signed by the enrollment agent, certificate issuance through CES and the CA, and then PKINIT for the user. The generated user certificate and private key are temporary on Linux; CA issuance records persist.

![Privileged enrollment: Linux resolves the caller, enrolls through CES and AD CS, then obtains a user TGT through PKINIT.](output/pdf/svg/02-enrollment-sequence.svg)

Follow [mode 1 setup](source/README.md#mode-1-setup-privileged-certificate-enrollment) and [enrollment-agent restrictions](docs/03-Enrollment-Agent-Restrictions.md). Administrators configure the template, agent, CES transport, directory keytab, trusted issuers and CRLs, and CA-enforced recipient restrictions.

The service account uses its keytab for LDAP/GSSAPI and, with `ces_auth=negotiate`, CES HTTP authentication. A separate mTLS identity can authenticate CES transport instead. The enrollment-agent signature authorizes the EOBO request independently of transport authentication.

## Mode 2: Privileged credential linking

Linux orchestrates acquisition without enrolling a user certificate: the service account binds to a writable DC, resolves the caller's AD account, adds one temporary public-key credential to `msDS-KeyCredentialLink`, and performs Key Trust PKINIT against that same DC. CRAFT removes its entry before publishing the TGT and preserves existing keys. Failed cleanup blocks cache publication and reports the residual credential for administrator action.

![Privileged credential linking: Linux adds a temporary AD key, obtains a user TGT through Key Trust PKINIT, removes the key, and publishes the cache.](output/pdf/svg/03-credential-linking-sequence.svg)

Follow [mode 2 setup](source/README.md#mode-2-setup-privileged-credential-linking) and [Key Trust delegation](docs/04-Key-Credential-Link-Delegation.md). Delegate only the required attribute access over approved ordinary users. This path requires no user-certificate CA enrollment, CES, enrollment agent or user template; it still requires a PKINIT-capable KDC with a trusted KDC certificate and current CRLs.

## Mode 3: Unprivileged Windows-exported certificate

Run the Windows certificate helper as the intended domain user without elevation to enroll and export the certificate. Linux uses the transferred certificate and matching unencrypted private key at `~/.config/craft/user.pem` and `user.key` for PKINIT. CRAFT runs as the caller and leaves the supplied PEM files in place. Users replace the pair before certificate expiry.

![Unprivileged mode: enroll and export a certificate on Windows, securely transfer the PEM pair to Linux, and run CRAFT as the user for PKINIT.](output/pdf/svg/04-windows-exported-certificate.svg)

Follow [mode 3 setup](source/README.md#mode-3-setup-unprivileged-windows-exported-certificate), including the [Windows certificate helper](scripts/Request-CRAFT-Certificate.cmd). Host installation and public trust configuration require an administrator, but Linux acquisition needs no setuid bit, service account, keytab, LDAP lookup, CES or `/run/craft`.

## Components and paths

| Component | Path or value | Modes |
| --- | --- | --- |
| Launcher, worker, optional maintainer | `/usr/local/bin/craft`, `/usr/local/libexec/craft-worker`, `/usr/local/bin/craft-maintain` | All |
| Public configuration and trust | `/etc/craft/`, root-controlled and readable by callers | All |
| Supplied certificate and key | NSS home `~/.config/craft/user.pem` and `user.key` | 3; also takes priority on installations for 1 or 2 |
| Service account and private runtime | `craft:craft`, `/run/craft/` mode 0700 | 1 and 2 |
| Approved caller group | `craft-users`; service credentials remain inaccessible to it | 1 and 2 |
| Credential cache | NSS home `.krb5cc_craft`, caller-owned mode 0600 | All |
| Optional command wrapper | [`with-craft`](source/scripts/with-craft) | All |

## Build and use

Install the [Linux dependencies](source/README.md#build), then run from the repository root:

```sh
git clone https://github.com/nomorefood/craft.git
cd craft
cmake -S source -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Follow the setup link for your chosen mode. Each recipe starts with the [shared Linux installation](source/README.md#shared-linux-installation); modes 1 and 2 add the [privileged installation](source/README.md#shared-privileged-installation). Configuration ships disabled; replace placeholders and complete setup before enabling acquisition. Then run as the intended non-root Linux user:

```sh
cache=$(/usr/local/bin/craft) || exit "$?"
export KRB5CCNAME="$cache"
klist -ef -c "$KRB5CCNAME"
```

Applications select the cache through `KRB5CCNAME` and use its TGT to obtain service tickets for SMB, LDAP and Kerberos-enabled web services. Access follows the user's existing permissions. CRAFT requests ten-hour TGT validity, seven-day renewal and AES256/AES128 encryption; the KDC controls the actual grant.

Strict validation rejects shortened initial or renewal grants without replacing the cache. An administrator can set `require_full_tgt_lifetime=no` to accept shorter grants with a warning.

For long-running jobs, start the ordinary `craft-maintain` executable once:

```sh
job_pid=$$
cache=$(/usr/local/bin/craft-maintain --watch-pid "$job_pid") || exit "$?"
export KRB5CCNAME="$cache"
```

Renewal uses the cache alone. Fresh authentication invokes `craft` and applies the same three-mode selection: reuse the home pair, or use the configured enrollment or credential-linking mode when both files are absent. Maintenance stops with the watched job. See [long-running jobs](source/README.md#long-running-jobs) for setup, status and limits.

Stopping maintenance, removing a linked key or deleting a certificate does not revoke an issued ticket.

## Documentation

| Guide | Contents |
| --- | --- |
| [Build and installation](source/README.md) | Complete setup for all three modes, configuration and usage |
| [Process overview](docs/01-CRAFT-Process-Overview.docx) ([PDF](docs/01-CRAFT-Process-Overview.pdf)) | All three mode diagrams, identity, storage and ticket lifecycle |
| [Configuration and validation](docs/02-CRAFT-Configuration-and-Validation.docx) ([PDF](docs/02-CRAFT-Configuration-and-Validation.pdf)) | Mode-specific setup, certificate profiles and acceptance checks |
| [Enrollment-agent restrictions](docs/03-Enrollment-Agent-Restrictions.md) | Mode 1 authorization and denial tests |
| [Key Trust delegation](docs/04-Key-Credential-Link-Delegation.md) | Mode 2 attribute delegation, cleanup and denial tests |
| [Validation and tests](source/TESTING.md) | Offline checks and live acceptance for each mode |
| [Security review notes](source/SECURITY.md) | Trust assumptions, privilege boundaries and limitations |

### Diagram sources and downloads

| Diagram | Image | Editable vector |
| --- | --- | --- |
| Three-mode selection | [PNG](output/pdf/png/craft-diagram-1.png) | [SVG](output/pdf/svg/01-system-overview.svg) |
| Mode 1: enrollment and PKINIT | [PNG](output/pdf/png/craft-diagram-2.png) | [SVG](output/pdf/svg/02-enrollment-sequence.svg) |
| Mode 2: credential linking and PKINIT | [PNG](output/pdf/png/craft-diagram-3.png) | [SVG](output/pdf/svg/03-credential-linking-sequence.svg) |
| Mode 3: Windows export and unprivileged PKINIT | [PNG](output/pdf/png/craft-diagram-4.png) | [SVG](output/pdf/svg/04-windows-exported-certificate.svg) |
| Credential timing | [PNG](output/pdf/png/craft-diagram-5.png) | [SVG](output/pdf/svg/05-credential-timing.svg) |
| Long-running job maintenance | [PNG](output/pdf/png/craft-diagram-6.png) | [SVG](output/pdf/svg/06-job-maintenance.svg) |

[All diagrams (PDF)](output/pdf/CRAFT-Timing-and-Architecture.pdf) · [Diagram generator](output/pdf/build_craft_diagrams.py) · [Word guide generator](docs/build_craft_guides.py)

## Project status

CRAFT is a reference implementation. Review the [validation record](source/TESTING.md) and complete the live checks for your chosen mode before production use. It supports automation alongside MFA-protected interactive sign-in, but does not perform an MFA challenge or establish that one was completed. Authentication depends on the supplied certificate and KDC mapping, CA-authorized enrollment, or the delegated directory write.

No real keys, certificates, keytabs or tickets are bundled.

## License

Source code, scripts, configuration examples and documentation are licensed under [GNU GPL version 3 only](LICENSE) (`GPL-3.0-only`).
