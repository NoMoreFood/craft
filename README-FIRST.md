# CRAFT - Certificate Request Agent for Tickets

CRAFT obtains Kerberos credentials noninteractively from a trusted, administrator-managed Linux endpoint, including a host that is not domain-joined. Users can supply a certificate and private key in their home directory for an entirely unprivileged workflow. When that pair is absent, an authorized deployment can obtain a short-lived credential on the user's behalf — either by CA enrollment-on-behalf-of or by a temporary directory Key Trust key. All paths support unattended scripts and Kerberos-aware applications without retaining the user's AD password.

This supports automation alongside MFA-protected interactive sign-in. CRAFT does not perform an MFA challenge or establish that the user completed one. Authentication depends on the supplied certificate and KDC account mapping, on administrator-authorized enrollment and CA restrictions, or on a narrowly delegated `msDS-KeyCredentialLink` write.

## Access Active Directory Resources

After authentication, the user selects the resulting credential cache for an application, typically through `KRB5CCNAME`. The Kerberos library uses the cached ticket-granting ticket (TGT) to request service tickets from the domain controller for the target services. Those tickets let the application authenticate as the user to resources such as SMB file shares, LDAP directories, and Kerberos-enabled web services, where supported and configured. Access remains subject to the user's permissions and the service's policy; obtaining a ticket does not grant additional access rights.

## Start Here

- [Process overview](docs/01-CRAFT-Process-Overview.docx) ([PDF](docs/01-CRAFT-Process-Overview.pdf)): enrollment, identity, certificate storage, ticket lifetimes, and everyday use.
- [Configuration and validation](docs/02-CRAFT-Configuration-and-Validation.docx) ([PDF](docs/02-CRAFT-Configuration-and-Validation.pdf)): both certificate profiles, installation and lab acceptance.
- [Build and installation guide](source/README.md): C++20 project, configuration, dependencies and tests.
- [Windows lab provisioning helper](scripts/Configure-CRAFT-CA.ps1): partial CA/template setup; review before use.
- [Key Trust delegation helper](scripts/Grant-CRAFTKeyCredentialLink.ps1) and [its authorization boundary](docs/04-Key-Credential-Link-Delegation.md): least-privilege `msDS-KeyCredentialLink` delegation for the `key_trust` fallback.
- [Windows certificate helper](scripts/Request-CRAFT-Certificate.cmd): request a user certificate from an eligible CA and export the home PEM pair without elevation.

## Components and Paths

| Component | Path / Value |
| --- | --- |
| Launcher / worker / maintainer | `craft` / `craft-worker` / `craft-maintain` |
| Public configuration and trust | `/etc/craft/`, root-controlled and readable by callers |
| Optional home certificate and key | `~/.config/craft/user.pem` / `user.key` |
| Privileged fallback runtime | `/run/craft/`, needed by enrollment and Key Trust |
| Service account/group / caller group | `craft` / `craft-users`; used by enrollment and Key Trust; unnecessary for a home-only installation |
| Credential cache | `.krb5cc_craft` in the caller's trusted home |
| Optional wrapper | `with-craft` |

## Choose the Certificate Workflow

`craft` checks the actual caller's `~/.config/craft/user.pem` and `user.key` first. A complete PEM pair uses the caller's privileges throughout certificate processing and Kerberos operations. Install `craft`, `craft-worker` and optional `craft-maintain` as ordinary mode-0755 executables; provide readable, root-controlled configuration and public trust/CRL files. No service account, directory keytab, LDAP lookup, CES or enrollment agent is required. Follow [home-certificate installation](source/README.md#home-certificate-installation).

The private key must be unencrypted PEM with private permissions such as 0600. Both files must be caller-owned regular files, without symlinks or additional hard links, nonempty and at most 1 MiB each. Their directories must belong to the caller and not be group/world-writable. CRAFT keeps these supplied files in place. A malformed, expired, revoked, incomplete or unsafe pair fails without replacing the cache or selecting enrollment.

To obtain a pair on Windows, run `Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate"` as the intended domain user. Supply the template's internal name or OID and a local destination directory. The template must permit direct user enrollment and exportable software keys. The helper uses Windows AD enrollment policy to select a CA and writes `user.pem` and `user.key`; transfer them securely to the Linux home paths. Follow [Windows certificate requests](source/README.md#request-a-home-certificate-on-windows) for requirements and preview mode.

On repeat runs, the helper reuses its pair until less than one calendar month remains, then obtains a replacement and removes the old Windows-store certificate. `/RenewBeforeDays N` overrides the window with a day-based period. `/DeleteAfterExport` removes the current Windows-store certificate after successful export or reuse and defaults off; it leaves the PEM files available for Linux. Run the helper again to check renewal and transfer replacement files before the Linux pair expires.

Replacements must pass the local CRAFT certificate-profile checks before publication. The helper recovers interrupted file updates, retries pending certificate cleanup, and preserves private-key containers shared by other certificates. The CMD entry point uses Windows PowerShell's built-in modules when invoked from PowerShell 7.

When neither file exists, a privileged installation uses a configured fallback through its dedicated service account. `mechanism=enrollment` uses directory lookup, an enrollment-agent signature and CES; see [enrollment installation](source/README.md#enrollment-installation) and [enrollment agent restrictions](docs/03-Enrollment-Agent-Restrictions.md). `mechanism=key_trust` writes a temporary key to the caller's `msDS-KeyCredentialLink`, authenticates with Key Trust PKINIT and removes it, with no CA, CES or enrollment agent; see [Key Trust installation](source/README.md#key-trust-installation) and [Key Trust delegation](docs/04-Key-Credential-Link-Delegation.md). Both fallbacks require the compiled setuid launcher. A home-only installation reports that the fallback is unavailable when no pair exists.

All paths request `<Linux username>@<configured realm>` and validate the returned ticket. The KDC decides whether the selected certificate or Key Trust key maps to that account; home mode does not query the directory UPN.

## Long-running jobs

Start `craft-maintain` once as the batch user to renew TGTs and obtain fresh credentials near the renewal deadline. Fresh authentication applies the same home-pair priority as `craft`. Replace a supplied certificate before expiry; CRAFT does not renew the certificate. Maintenance stops with the watched job, and the cache remains. Follow the [usage guide](source/README.md#long-running-jobs) for startup, setup and status.

## Certificate and Ticket Storage

Home mode reads the persistent certificate and private key supplied by the user. It releases its in-memory copies and sealed PKINIT memory files at the end of the operation, while leaving `user.pem` and `user.key` in place. Enrollment generates a fresh key and certificate for each attempt and releases them after PKINIT without saving a user PEM/PFX file or certificate-store entry. CA records remain independently.

The `.krb5cc_craft` cache persists in either mode and contains the TGT and session key, without the certificate/private key. Renewal uses the cache alone. Memory and memory files can reach swap or privileged host capture; deleting a key or certificate does not revoke an issued ticket. See [certificate storage and cleanup](source/README.md#certificate-storage-and-cleanup).

## Defaults and Limitations

Both workflows request a ten-hour initial TGT and seven-day renewal window, with AES256/AES128 session and ticket encryption. The KDC controls the grant; certificate/key lifetime can constrain initial validity. Strict mode rejects shortened grants without replacing the cache. `require_full_tgt_lifetime=no` explicitly accepts shorter grants with a warning.

Enrollment pins the configured template, directory-resolved UPN and all three client EKUs, with a default ten-hour total certificate-validity cap including backdating. Home mode accepts ordinary certificate validity and templates, requires Smart Card Logon or PKINIT Client Authentication EKU, a valid UPN SAN, digitalSignature usage, matching key, CA:FALSE, trusted chain and current CRLs. Its KDC mapping and returned-principal checks bind authentication to the caller's Linux username and configured realm.

Key Trust generates a short-lived self-signed certificate for the directory-resolved UPN, checks the same logon usage and key match, and relies on the `msDS-KeyCredentialLink` key the KDC validates rather than a CA chain. It requires a domain that supports Key Trust (NGC) authentication and a narrowly delegated attribute write, and removes the temporary key after authentication. All paths still request `<Linux username>@<realm>` and validate the returned ticket.

`certificate_cn={user}` controls only an enrollment CSR. Supported tokens are `{user}`, `{upn}` and `{domain}`. It does not alter a supplied home certificate or the Kerberos principal.

## Build

On Linux, install the [required dependencies](source/README.md#build), then run from the repository root:

```sh
cmake -S source -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Follow the [installation guide](source/README.md#install-in-an-isolated-lab-after-reviewing-the-source), adjusting its `build/` paths if using the root-level build above. Configuration ships disabled. Choose the home-only or enrollment installation and provide the corresponding credentials, public trust anchors and current CRLs before a lab trial.

## Validation Status

The repository includes synthetic offline tests; see [TESTING.md](source/TESTING.md) for reproducible commands and live acceptance checks. Offline success does not establish CES/PKINIT interoperability or validate the installed setuid boundary. No real keys, certificates, keytabs or tickets are bundled.

## License

CRAFT source code, scripts, configuration examples, and documentation are licensed under the GNU General Public License, version 3 (SPDX: `GPL-3.0-only`). See [LICENSE](LICENSE) for the full terms. This material is provided without warranty, as described in the license.
