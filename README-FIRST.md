# CRAFT - Certificate Request Agent for Tickets

CRAFT obtains Kerberos credentials noninteractively from a trusted, administrator-managed Linux endpoint, including a host that is not domain-joined. Users can supply a certificate and private key in their home directory for an entirely unprivileged workflow. When that pair is absent, an authorized deployment can enroll a short-lived certificate on the user's behalf. Both paths support unattended scripts and Kerberos-aware applications without retaining the user's AD password.

This supports automation alongside MFA-protected interactive sign-in. CRAFT does not perform an MFA challenge or establish that the user completed one. Authentication depends on the supplied certificate and KDC account mapping, or on administrator-authorized enrollment and CA restrictions.

## Access Active Directory Resources

After authentication, the user selects the resulting credential cache for an application, typically through `KRB5CCNAME`. The Kerberos library uses the cached ticket-granting ticket (TGT) to request service tickets from the domain controller for the target services. Those tickets let the application authenticate as the user to resources such as SMB file shares, LDAP directories, and Kerberos-enabled web services, where supported and configured. Access remains subject to the user's permissions and the service's policy; obtaining a ticket does not grant additional access rights.

## Start Here

- [Process overview](docs/01-CRAFT-Process-Overview.docx) ([PDF](docs/01-CRAFT-Process-Overview.pdf)): enrollment, identity, certificate storage, ticket lifetimes, and everyday use.
- [Configuration and validation](docs/02-CRAFT-Configuration-and-Validation.docx) ([PDF](docs/02-CRAFT-Configuration-and-Validation.pdf)): both certificate profiles, installation and lab acceptance.
- [Build and installation guide](source/README.md): C++20 project, configuration, dependencies and tests.
- [Windows lab provisioning helper](scripts/Configure-CRAFT-CA.ps1): partial CA/template setup; review before use.

## Components and Paths

| Component | Path / Value |
| --- | --- |
| Launcher / worker / maintainer | `craft` / `craft-worker` / `craft-maintain` |
| Public configuration and trust | `/etc/craft/`, root-controlled and readable by callers |
| Optional home certificate and key | `~/.config/craft/user.pem` / `user.key` |
| Enrollment runtime | `/run/craft/`, needed only for enrollment |
| Enrollment service account/group / caller group | `craft` / `craft-users`; unnecessary for a home-only installation |
| Credential cache | `.krb5cc_craft` in the caller's trusted home |
| Optional wrapper | `with-craft` |

## Choose the Certificate Workflow

`craft` checks the actual caller's `~/.config/craft/user.pem` and `user.key` first. A complete PEM pair uses the caller's privileges throughout certificate processing and Kerberos operations. Install `craft`, `craft-worker` and optional `craft-maintain` as ordinary mode-0755 executables; provide readable, root-controlled configuration and public trust/CRL files. No service account, directory keytab, LDAP lookup, CES or enrollment agent is required. Follow [home-certificate installation](source/README.md#home-certificate-installation).

The private key must be unencrypted PEM with private permissions such as 0600. Both files must be caller-owned regular files, without symlinks or additional hard links, nonempty and at most 1 MiB each. Their directories must belong to the caller and not be group/world-writable. CRAFT keeps these supplied files in place. A malformed, expired, revoked, incomplete or unsafe pair fails without replacing the cache or selecting enrollment.

When neither file exists, an enrollment-enabled installation uses its dedicated service account, directory lookup, enrollment-agent signature and CES. This path requires the compiled setuid launcher and CA recipient restrictions. See [enrollment installation](source/README.md#enrollment-installation). A home-only installation reports that enrollment is unavailable when no pair exists.

Both paths request `<Linux username>@<configured realm>` and validate the returned ticket. The KDC decides whether the selected certificate maps to that account; home mode does not query the directory UPN.

## Long-running jobs

Start `craft-maintain` once as the batch user to renew TGTs and obtain fresh credentials near the renewal deadline. Fresh authentication applies the same home-pair priority as `craft`. Replace a supplied certificate before expiry; CRAFT does not renew the certificate. Maintenance stops with the watched job, and the cache remains. Follow the [usage guide](source/README.md#long-running-jobs) for startup, setup and status.

## Certificate and Ticket Storage

Home mode reads the persistent certificate and private key supplied by the user. It releases its in-memory copies and sealed PKINIT memory files at the end of the operation, while leaving `user.pem` and `user.key` in place. Enrollment generates a fresh key and certificate for each attempt and releases them after PKINIT without saving a user PEM/PFX file or certificate-store entry. CA records remain independently.

The `.krb5cc_craft` cache persists in either mode and contains the TGT and session key, without the certificate/private key. Renewal uses the cache alone. Memory and memory files can reach swap or privileged host capture; deleting a key or certificate does not revoke an issued ticket. See [certificate storage and cleanup](source/README.md#certificate-storage-and-cleanup).

## Defaults and Limitations

Both workflows request a ten-hour initial TGT and seven-day renewal window, with AES256/AES128 session and ticket encryption. The KDC controls the grant; certificate/key lifetime can constrain initial validity. Strict mode rejects shortened grants without replacing the cache. `require_full_tgt_lifetime=no` explicitly accepts shorter grants with a warning.

Enrollment pins the configured template, directory-resolved UPN and all three client EKUs, with a default ten-hour total certificate-validity cap including backdating. Home mode accepts ordinary certificate validity and templates, requires Smart Card Logon or PKINIT Client Authentication EKU, a valid UPN SAN, digitalSignature usage, matching key, CA:FALSE, trusted chain and current CRLs. Its KDC mapping and returned-principal checks bind authentication to the caller's Linux username and configured realm.

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
