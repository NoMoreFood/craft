# CRAFT - Certificate Request Agent for Tickets

CRAFT obtains Kerberos credentials on behalf of an approved user, noninteractively, from a trusted and administrator-managed Linux endpoint. It supports unattended scripts and Kerberos-aware applications that need to access Active Directory resources as that user, even when the Linux host is not domain-joined. A short-lived certificate provides the authentication path, so automation does not need to collect, store, or replay the user's AD password.

This is useful where interactive sign-in is protected by two-factor or multifactor authentication and retaining a reusable user password for automation would undermine that approach. Administrators explicitly authorize a separate certificate-enrollment path for selected users and trusted hosts. CRAFT does not perform an MFA challenge or establish that the user has completed one; its authority comes from the managed endpoint, enrollment credentials, and CA restrictions.

## Access Active Directory Resources

After enrollment and authentication, the user selects the resulting credential cache for an application, typically through `KRB5CCNAME`. The Kerberos library uses the cached ticket-granting ticket (TGT) to request service tickets from the domain controller for the target services. Those tickets let the application authenticate as the user to resources such as SMB file shares, LDAP directories, and Kerberos-enabled web services, where supported and configured. Access remains subject to the user's permissions and the service's policy; obtaining a ticket does not grant additional access rights.

## Start Here

- [Process overview](docs/01-CRAFT-Process-Overview.docx) ([PDF](docs/01-CRAFT-Process-Overview.pdf)): enrollment, identity, certificate storage, ticket lifetimes, and everyday use.
- [Configuration and validation](docs/02-CRAFT-Configuration-and-Validation.docx) ([PDF](docs/02-CRAFT-Configuration-and-Validation.pdf)): certificate profile and lab acceptance.
- [Build and installation guide](source/README.md): C++20 project, configuration, dependencies and tests.
- [Windows lab provisioning helper](scripts/Configure-CRAFT-CA.ps1): partial CA/template setup; review before use.

## Components and Paths

| Component | Path / Value |
| --- | --- |
| Launcher / worker / maintainer | `craft` / `craft-worker` / `craft-maintain` |
| Configuration / runtime | `/etc/craft/` / `/run/craft/` |
| Service account/group / caller group | `craft` / `craft-users` |
| Credential cache | `.krb5cc_craft` in the caller's trusted home |
| Optional wrapper | `with-craft` |

## Long-running jobs

Start `craft-maintain` once as the batch user to renew TGTs and obtain fresh credentials near the renewal deadline.
It runs in the background and stops with the watched job; no cron entry or wrapper is needed.
Follow the [usage guide](source/README.md#long-running-jobs) for startup, host setup and status.

## Certificate and Ticket Storage

The issued user certificate and private key are temporary on the Linux client and are not exported to persistent files or a certificate store. They are released when the operation ends; the CA may retain its issued certificate and audit records. The user's `.krb5cc_craft` ticket cache persists independently. Memory may still be exposed through swap or privileged host access. See [certificate storage and cleanup](source/README.md#certificate-storage-and-cleanup) for details.

## Defaults and Limitations

The default certificate profile accepts at most ten hours TOTAL validity, including backdating. The CA must issue that profile; the client does not set CA dates. The user TGT request matches the most permissive DISA STIG guidance for domain controllers: ten hours (36000 seconds) of initial ticket validity with seven days (604800 seconds) of renewal validity. AES256/AES128 session and outer-ticket encryption are required. User identity (SID and UPN) is resolved dynamically via Active Directory Global Catalog lookups; the real runtime UID/NSS name remains checked.

IMPORTANT: Under DISA STIG for Windows Server Domain Controllers, initial user tickets are capped at 10 hours and renewals at 7 days. Additionally, RFC 4556 certificate/key-lifetime constraints constrain initial tickets by client certificate validity, requiring a 10-hour certificate template. The program does not bypass KDC policy or rewrite tickets. Default strict mode rejects shorter grants without replacing the current cache. Set `require_full_tgt_lifetime=no` only to explicitly accept a shorter ticket with a warning.

Customize the requested CN in [config.example](source/config/config.example): `certificate_cn={user}`. Supported tokens are `{user}`, `{upn}` and `{domain}`. The CA may override the requested subject; CN changes do not change the approved identity.

## Build

On Linux, install the [required dependencies](source/README.md#build), then run from the repository root:

```sh
cmake -S source -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Follow the [installation guide](source/README.md#install-in-an-isolated-lab-after-reviewing-the-source), adjusting its `build/` paths if using the root-level build above. Configuration ships disabled. Supply CA/transport credentials, trust anchors, current CRLs and actual endpoint/template values before a lab trial.

## Validation Status

The repository includes synthetic offline tests; see [TESTING.md](source/TESTING.md) for reproducible commands and live acceptance checks. Offline success does not establish CES/PKINIT interoperability or validate the installed setuid boundary. No real keys, certificates, keytabs or tickets are bundled.

## License

CRAFT source code, scripts, configuration examples, and documentation are licensed under the GNU General Public License, version 3 (SPDX: `GPL-3.0-only`). See [LICENSE](LICENSE) for the full terms. This material is provided without warranty, as described in the license.
