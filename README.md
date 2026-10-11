# CRAFT Certificate Request Agent for Tickets

CRAFT obtains a user's Kerberos ticket-granting ticket (TGT) from Linux through certificate-based authentication (PKINIT), including on hosts that are not domain-joined. It publishes a private ticket cache for unattended scripts and Kerberos-aware applications without storing the user's Active Directory password.

## Choose an operating mode

| Mode | Credential and authorization | Linux installation | Setup |
| --- | --- | --- | --- |
| **1. Privileged certificate enrollment** | AD CS issues a temporary user certificate through CES; the CA restricts the enrollment agent, template and recipients. | Setuid launcher and dedicated service account | [Mode 1 setup](source/README.md#mode-1-setup-privileged-certificate-enrollment) |
| **2. Privileged credential linking (Key Trust)** | CRAFT temporarily adds a public key to the user's `msDS-KeyCredentialLink`; scoped AD delegation authorizes the write. | Setuid launcher and dedicated service account | [Mode 2 setup](source/README.md#mode-2-setup-privileged-credential-linking) |
| **3. Unprivileged Windows-exported certificate** | The user enrolls and exports a certificate on Windows, transfers the PEM pair to Linux, and the KDC maps it to the account. | Ordinary executables running as the caller | [Mode 3 setup](source/README.md#mode-3-setup-unprivileged-windows-exported-certificate) |

A complete `~/.config/craft/user.pem` and `user.key` pair takes priority in every installation. Partial, unsafe or invalid inputs fail without using either privileged mechanism. Only when both files are absent does `mechanism=enrollment` or `mechanism=key_trust` select a privileged mode. An ordinary installation requires a valid PEM pair.

Users run `craft` directly, without `sudo`. All modes request `<Linux username>@<configured realm>`, validate the returned TGT and publish a caller-owned mode-0600 `.krb5cc_craft` in the home resolved by the Linux account database (NSS). Certificate and network processing run as the caller or the dedicated service account. Every mode needs administrator-controlled Kerberos configuration, KDC trust and current CRLs; modes 1 and 3 also validate the user certificate's CA chain and revocation.

![CRAFT checks the supplied home pair before selecting the configured privileged mechanism.](docs/diagrams/01-system-overview.svg)

## Compile install and validate

Install the [Linux dependencies](source/README.md#build), then compile as an ordinary user:

```sh
git clone https://github.com/nomorefood/craft.git
cd craft
cmake -S source -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Complete [shared Linux installation](source/README.md#shared-linux-installation), then the setup for your chosen mode. Modes 1 and 2 also need the [privileged installation](source/README.md#shared-privileged-installation). Configuration ships disabled; replace the examples, provision trust and credentials, and complete the [deployment acceptance checks](source/TESTING.md) before production use.

## Use the ticket cache

Run as the intended non-root Linux user:

```sh
cache=$(/usr/local/bin/craft) || exit "$?"
export KRB5CCNAME="$cache"
klist -ef -c "$KRB5CCNAME"
```

Kerberos-aware applications launched from that shell use the cache to obtain service tickets for SMB, LDAP and Kerberos-enabled web services. Access follows the user's existing permissions. CRAFT requests ten-hour TGT validity, seven-day renewal and AES256/AES128 encryption; the KDC controls the grant. Strict validation rejects shortened grants. Administrators can explicitly accept them with `require_full_tgt_lifetime=no`.

For long-running jobs, start maintenance once from the job script:

```sh
job_pid=$$
cache=$(/usr/local/bin/craft-maintain --watch-pid "$job_pid") || exit "$?"
export KRB5CCNAME="$cache"
```

Renewal uses the cache alone. Fresh authentication invokes `craft` with the same mode selection. Maintenance stops with the watched job and leaves the cache. Replace supplied certificates before expiry; ticket maintenance does not renew them. See [long-running jobs](source/README.md#long-running-jobs) for scheduler requirements and status.

## Administrator documentation

| Guide | Purpose |
| --- | --- |
| [Build installation and configuration](source/README.md) | Dependencies, installation recipes, all configuration settings, Windows helpers and troubleshooting |
| [Process overview](docs/01-CRAFT-Process-Overview.docx) ([PDF](docs/01-CRAFT-Process-Overview.pdf)) | Operating modes, identity, credential storage and ticket lifecycle |
| [Configuration and validation](docs/02-CRAFT-Configuration-and-Validation.docx) ([PDF](docs/02-CRAFT-Configuration-and-Validation.pdf)) | Printable mode requirements, configuration and acceptance checks |
| [Enrollment-agent restrictions](docs/03-Enrollment-Agent-Restrictions.md) | Mode 1 CA authorization and denial tests |
| [Key Trust delegation](docs/04-Key-Credential-Link-Delegation.md) | Mode 2 directory permissions, cleanup and denial tests |
| [Deployment validation](source/TESTING.md) | Offline checks, recorded coverage and live acceptance |
| [Security and operations](source/SECURITY.md) | Credential authority, trust boundaries and operational disable |

[All diagrams (PDF)](docs/CRAFT-Diagrams.pdf). Individual SVGs: [mode selection](docs/diagrams/01-system-overview.svg), [enrollment](docs/diagrams/02-enrollment-sequence.svg), [credential linking](docs/diagrams/03-credential-linking-sequence.svg), [Windows export](docs/diagrams/04-windows-exported-certificate.svg), [credential timing](docs/diagrams/05-credential-timing.svg), and [job maintenance](docs/diagrams/06-job-maintenance.svg).

## Validation scope

Recorded AD lab runs cover Ubuntu 24.04.5 LTS and Rocky Linux 9.8 clients, Windows Server 2022 AD/AD CS/CES, and Windows Server 2019/2025 member servers. Additional Linux build and MIT KDC checks have narrower scope. See the [validation record](source/TESTING.md#recorded-validation) for results and limitations; other deployments need their own acceptance checks.

CRAFT is a reference implementation. It does not perform an MFA challenge or establish that one was completed. Protect the host, enrollment authority, directory delegation, supplied keys and ticket caches. Removing credentials, stopping maintenance or deleting a cache does not revoke already-issued tickets. No real credentials are bundled.

## License

Source code, scripts, configuration examples and documentation are licensed under [GNU GPL version 3 only](LICENSE) (`GPL-3.0-only`).
