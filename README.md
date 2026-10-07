# CRAFT: Certificate Request Agent for Tickets

CRAFT obtains Kerberos credentials noninteractively from a trusted, administrator-managed Linux endpoint, including a host that is not domain-joined. Users can supply a certificate and private key in their home directory for an entirely unprivileged workflow. When that pair is absent, an authorized deployment can enroll a short-lived certificate on the user's behalf. Both paths support unattended scripts and Kerberos-aware applications without retaining the user's AD password.

This supports automation alongside MFA-protected interactive sign-in. CRAFT does not perform an MFA challenge or establish that the user completed one. Authentication depends on the supplied certificate and KDC account mapping, or on administrator-authorized enrollment and CA restrictions.

## How it works

1. Resolve the invoking Linux user's real UID, NSS username and home directory.
2. Look for `~/.config/craft/user.pem` and `~/.config/craft/user.key` using the caller's permissions. A complete pair takes priority; partial, unsafe or invalid inputs fail without enrollment fallback.
3. If both files are absent, use the configured enrollment path: resolve the AD UPN, generate a temporary RSA key and EOBO request, and obtain a certificate through CES and the CA.
4. Validate the selected certificate and key against the applicable certificate policy, configured trust chain and current CRLs.
5. Use MIT Kerberos PKINIT for `<Linux username>@<configured realm>`. The KDC enforces certificate-to-account mapping; CRAFT checks the returned TGT.
6. Atomically publish a mode-0600 `.krb5cc_craft` cache in the invoking user's home.

Applications select the cache through `KRB5CCNAME` and use its TGT to obtain service tickets for SMB, LDAP and Kerberos-enabled web services. Access follows the user's existing service permissions.

## Use a certificate from your home directory

Place an existing certificate and its matching unencrypted private key at the fixed paths below. Use PEM format; PFX loading and passphrase prompts are unsupported.

To obtain that pair from AD CS, run the [Windows certificate helper](scripts/Request-CRAFT-Certificate.cmd) from CMD or Windows PowerShell as the intended domain user:

```bat
.\scripts\Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate"
```

Windows enrollment policy selects an eligible CA for the template's internal name or OID. Choose a template allowing direct user enrollment and exportable software keys, with the logon usages and identity mapping required by the KDC. The helper writes `user.pem` and an unencrypted PKCS#8 `user.key` to the destination without elevation or OpenSSL. Transfer the pair securely to Linux, then install it as shown below. See [Windows certificate requests](source/README.md#request-a-home-certificate-on-windows) for prerequisites, preview and failure handling.

Repeat the command with the same template and destination to reuse the pair until less than one calendar month remains before expiration. `/RenewBeforeDays N` overrides that window with a day-based period. Renewal replaces the managed exports and removes their old Windows-store certificate after the new pair is ready. `/DeleteAfterExport` also removes the current Windows-store certificate after successful export or reuse; it defaults off. The helper checks when invoked and does not schedule renewal or replace Linux copies automatically.

```sh
mkdir -p ~/.config/craft
chmod 0700 ~/.config/craft
install -m 0600 /path/to/user-certificate.pem ~/.config/craft/user.pem
install -m 0600 /path/to/user-private-key.pem ~/.config/craft/user.key
cache=$(/usr/local/bin/craft) && export KRB5CCNAME="$cache"
```

The files must belong to the caller, be regular files without symlinks or extra hard links, and be nonempty and at most 1 MiB each. The key must be private; the home and certificate directories must not be group/world-writable. The location comes from NSS, so `$HOME` and `XDG_CONFIG_HOME` do not override it.

Certificate loading, validation, PKINIT and cache publication run as the caller. A regular mode-0755 installation needs no service account, enrollment keytab, LDAP lookup, CES or `/run/craft`. Public configuration, trust anchors and CRLs under `/etc/craft` remain administrator-controlled and must be readable by the caller. The certificate must map to the Linux username in the configured realm. See the [unprivileged installation guide](source/README.md#home-certificate-installation).

## Features

- Noninteractive user ticket acquisition from trusted Linux endpoints, with no stored user AD password.
- Home-directory PEM credentials take priority and work with a non-setuid installation.
- Detached TGT renewal and fresh authentication for long-running jobs, using the selected certificate source.
- AD CS enrollment-on-behalf-of using an administrator-provisioned enrollment-agent certificate.
- HTTP Negotiate or mutual TLS for CES transport, with LDAP/GSSAPI directory lookup.
- Enrollment validates the directory-resolved UPN; home certificates rely on KDC mapping to the fixed caller principal.
- AES128/AES256 Kerberos encryption, ten-hour requested TGT validity, and seven-day requested renewal.
- Temporary PKINIT key material passed through sealed Linux memory files.
- Synthetic offline tests and an optional PowerShell helper for Windows lab provisioning.

## Getting started

Install the [Linux build dependencies](source/README.md#build), then clone and build:

```sh
git clone https://github.com/nomorefood/craft.git
cd craft
cmake -S source -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Continue with the [deployment overview](README-FIRST.md) and [configuration and installation guide](source/README.md). Configuration ships disabled. The home-certificate workflow requires a public, root-controlled Kerberos/trust configuration and an existing certificate accepted by the KDC. Enrollment additionally requires administrator setup of the service account, CES and CA authorization.

## Long-running jobs

Start once from the batch script as the approved user:

```sh
job_pid=$$
cache=$(/usr/local/bin/craft-maintain --watch-pid "$job_pid") || exit "$?"
export KRB5CCNAME="$cache"
```

`craft-maintain` renews TGTs without certificates, obtains fresh credentials near the absolute renewal deadline, and stops with the watched process. Fresh authentication invokes `craft`, which reuses the home pair when present and enrolls only when it is absent. Keep a supplied certificate valid and replace it before it expires; CRAFT does not renew or delete those files. Use the job controller PID if the startup shell exits early. See the [usage guide](source/README.md#long-running-jobs) for setup, status and limits.

## Documentation

| Guide | Contents |
| --- | --- |
| [Deployment overview](README-FIRST.md) | Components, paths, defaults, and initial setup |
| [Build and installation](source/README.md) | Dependencies, AD CS preparation, configuration, and usage |
| [Validation and tests](source/TESTING.md) | Offline tests, recorded lab results, and live acceptance checks |
| [Security review notes](source/SECURITY.md) | Trust assumptions, implemented controls, and limitations |
| [Enrollment agent restrictions](docs/03-Enrollment-Agent-Restrictions.md) | CA authorization, privileged-account exclusion, key custody, and denial tests |
| [Process overview](docs/01-CRAFT-Process-Overview.docx) | Enrollment, service tickets, and credential lifecycle ([PDF](docs/01-CRAFT-Process-Overview.pdf)) |
| [Configuration and validation](docs/02-CRAFT-Configuration-and-Validation.docx) | Certificate profile and lab acceptance ([PDF](docs/02-CRAFT-Configuration-and-Validation.pdf)) |
| [Windows provisioning helper](scripts/Configure-CRAFT-CA.ps1) | Optional partial CA/template setup for a lab |
| [Windows certificate helper](scripts/Request-CRAFT-Certificate.cmd) | User enrollment and PEM export for the home-certificate workflow |

### Diagrams

| Diagram | Picture | Editable version |
| --- | --- | --- |
| System overview | [PNG](output/pdf/png/craft-diagram-1.png) | [SVG](output/pdf/svg/01-system-overview.svg) |
| Enrollment sequence when no home pair is present | [PNG](output/pdf/png/craft-diagram-2.png) | [SVG](output/pdf/svg/02-enrollment-sequence.svg) |
| Credential timing | [PNG](output/pdf/png/craft-diagram-3.png) | [SVG](output/pdf/svg/03-credential-timing.svg) |
| Long-running job maintenance | [PNG](output/pdf/png/craft-diagram-4.png) | [SVG](output/pdf/svg/04-job-maintenance.svg) |
| Unprivileged home-certificate workflow | [PNG](output/pdf/png/craft-diagram-5.png) | [SVG](output/pdf/svg/05-home-certificate-workflow.svg) |

[All diagrams (PDF)](output/pdf/CRAFT-Timing-and-Architecture.pdf)

## Project status

CRAFT is a reference implementation. Review the [validation record](source/TESTING.md) and validate your own CES, PKINIT, certificate-policy, and privilege-boundary configuration before production use. The KDC decides the ticket lifetime and renewal window. Certificate-based authentication here uses software keys and does not establish hardware possession or MFA.

## License

Source code, scripts, configuration examples, and documentation are licensed under [GNU GPL version 3 only](LICENSE) (`GPL-3.0-only`).
