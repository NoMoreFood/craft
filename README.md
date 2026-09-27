# CRAFT: Certificate Request Agent for Tickets

CRAFT obtains Kerberos credentials on behalf of an approved user, noninteractively, from a trusted and administrator-managed Linux endpoint. It supports unattended scripts and Kerberos-aware applications that need to access Active Directory resources as that user, even when the Linux host is not domain-joined. A short-lived certificate provides the authentication path, so automation does not need to collect, store, or replay the user's AD password.

This is useful where interactive sign-in is protected by two-factor or multifactor authentication and retaining a reusable user password for automation would undermine that approach. Administrators explicitly authorize a separate certificate-enrollment path for selected users and trusted hosts. CRAFT does not perform an MFA challenge or establish that the user has completed one; its authority comes from the managed endpoint, enrollment credentials, and CA restrictions.

## How it works

1. Resolve the invoking Linux user's identity through the Active Directory Global Catalog.
2. Generate a temporary RSA key and an enrollment-on-behalf-of (EOBO) certificate request.
3. Submit the request to AD CS Certificate Enrollment Web Service (CES) over HTTPS using MS-WSTEP.
4. Validate the issued certificate's identity, key, template, trust chain, revocation status, and lifetime.
5. Use MIT Kerberos PKINIT to obtain a ticket-granting ticket (TGT) from the domain controller.
6. Write a Kerberos credential cache to `.krb5cc_craft` in the invoking user's home directory.

After enrollment and authentication, the user selects the resulting credential cache for an application, typically through `KRB5CCNAME`. The Kerberos library uses the cached ticket-granting ticket (TGT) to request service tickets from the domain controller for the target services. Those tickets let the application authenticate as the user to resources such as SMB file shares, LDAP directories, and Kerberos-enabled web services, where supported and configured. Access remains subject to the user's permissions and the service's policy; obtaining a ticket does not grant additional access rights.

## Features

- Noninteractive user ticket acquisition from trusted Linux endpoints, with no stored user AD password.
- AD CS enrollment-on-behalf-of using an administrator-provisioned enrollment-agent certificate.
- HTTP Negotiate or mutual TLS for CES transport, with LDAP/GSSAPI directory lookup.
- Active Directory SID and UPN checks against the issued certificate.
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

Continue with the [deployment overview](README-FIRST.md) and [configuration and installation guide](source/README.md). Configuration ships disabled; deployment requires administrator setup of both the Linux host and the AD CS environment.

## Documentation

| Guide | Contents |
| --- | --- |
| [Deployment overview](README-FIRST.md) | Components, paths, defaults, and initial setup |
| [Build and installation](source/README.md) | Dependencies, AD CS preparation, configuration, and usage |
| [Validation and tests](source/TESTING.md) | Offline tests, recorded lab results, and live acceptance checks |
| [Security review notes](source/SECURITY.md) | Trust assumptions, implemented controls, and limitations |
| [Process overview](docs/01-CRAFT-Process-Overview.docx) | Enrollment, service tickets, and credential lifecycle ([PDF](docs/01-CRAFT-Process-Overview.pdf)) |
| [Configuration and validation](docs/02-CRAFT-Configuration-and-Validation.docx) | Certificate profile and lab acceptance ([PDF](docs/02-CRAFT-Configuration-and-Validation.pdf)) |
| [Windows provisioning helper](scripts/Configure-CRAFT-CA.ps1) | Optional partial CA/template setup for a lab |

## Project status

CRAFT is a reference implementation. Review the [validation record](source/TESTING.md) and validate your own CES, PKINIT, certificate-policy, and privilege-boundary configuration before production use. The KDC decides the ticket lifetime and renewal window. Certificate-based authentication here uses software keys and does not establish hardware possession or MFA.

## License

Source code, scripts, configuration examples, and documentation are licensed under [GNU GPL version 3 only](LICENSE) (`GPL-3.0-only`).
