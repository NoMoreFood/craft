# CRAFT build installation and configuration

This guide is for administrators compiling CRAFT on Linux, provisioning Active Directory and PKI prerequisites, and operating the installed system. CRAFT obtains the calling user's Kerberos credentials without storing the user's AD password. Modes 1-3 obtain a ticket-granting ticket (TGT) through PKINIT; mode 4 obtains only approved service tickets through a broker's constrained delegation. It does not perform an MFA challenge.

| Mode | Credential source | Linux acquisition identity | Setup |
| --- | --- | --- | --- |
| **1. Privileged certificate enrollment** | Temporary AD CS user certificate enrolled through CES with an enrollment-agent signature | Dedicated `craft` service account through the setuid launcher | [Mode 1](#mode-1-setup-privileged-certificate-enrollment) |
| **2. Privileged credential linking (Key Trust)** | Temporary public key in the user's `msDS-KeyCredentialLink` | Dedicated `craft` service account through the setuid launcher | [Mode 2](#mode-2-setup-privileged-credential-linking) |
| **3. Unprivileged Windows-exported certificate** | Persistent certificate and private-key PEM pair in the Linux user's home | Calling user through ordinary executables | [Mode 3](#mode-3-setup-unprivileged-windows-exported-certificate) |
| **4. Service tickets through constrained delegation** | Broker keytab with protocol transition and an explicit target SPN list | Dedicated `craft` service account through the setuid launcher | [Mode 4](#mode-4-setup-service-tickets-through-constrained-delegation) |

## Mode selection and process boundaries

Run `/usr/local/bin/craft` with no arguments as the intended non-root user, without `sudo`. CRAFT uses the real UID, NSS username and NSS home; `$USER`, `$HOME`, `SUDO_USER`, `XDG_CONFIG_HOME` and caller Kerberos overrides cannot select another identity. Linux usernames must match the intended AD `sAMAccountName`, be at most 64 characters, start with a lowercase letter or underscore, and contain only lowercase letters, digits, underscores, periods or hyphens.

`mechanism=constrained_delegation` selects mode 4 before inspecting any home PEM pair. It never invokes PKINIT, enrollment or Key Trust, including when a valid home pair exists. For the other mechanisms, a complete NSS-home `~/.config/craft/user.pem` and `user.key` pair selects mode 3, including on a setuid installation. Partial, unsafe or invalid inputs fail without privileged acquisition. Only an absent pair selects `mechanism=enrollment` (the default) or `mechanism=key_trust`; an ordinary installation then fails because it cannot use a privileged mode. CRAFT never switches between the privileged mechanisms after a failure.

All modes request `<Linux username>@<configured realm>`. The KDC enforces certificate mapping or broker delegation; CRAFT validates the returned principals, flags, encryption and ticket times. Mode 4 requires every configured service to succeed before publishing a cache, excluding broker credentials and S4U2Self evidence. Certificate, LDAP, CES and Kerberos work run as the caller or service account. The cache writer runs as the caller. See the [process overview](../docs/01-CRAFT-Process-Overview.pdf) for the acquisition diagrams.

## Build

Compile as an ordinary user on the target Linux distribution. Use supported, patched distribution packages meeting these minimum requirements:

| Requirement | Minimum or purpose |
| --- | --- |
| C++ compiler and standard library | C++20 with `std::format`, spans and ranges; GCC/libstdc++ 13.1 or equivalent |
| Build tools | CMake 3.16, make or another CMake build tool, pkg-config and Git |
| MIT Kerberos | `krb5_marshal_credentials` support: upstream 1.20 or the RHEL 8.5+/9 builds; Heimdal is unsupported |
| Worker libraries and development headers | OpenSSL 1.1.1, libcurl 7.61, libxml2 2.9, OpenLDAP and Cyrus SASL |
| Runtime plugins | MIT PKINIT in modes 1-3; MIT GSSAPI in mode 4; Cyrus SASL GSSAPI in modes 1 and 2; libcurl SPNEGO for CES Negotiate |
| Host facilities | `/proc`, memfd, a writable safe user home and a working `/dev/log` socket; setuid execution for modes 1, 2 and 4 |

On Ubuntu/Debian with a suitable compiler:

```sh
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config git libssl-dev libkrb5-dev \
    krb5-user krb5-pkinit libcurl4-openssl-dev libxml2-dev \
    libldap2-dev libsasl2-dev libsasl2-modules-gssapi-mit
```

On RHEL 8/9 and compatible distributions, enable the distribution repositories providing development packages and a supported GCC Toolset. For example:

```sh
sudo dnf install gcc-toolset-15 cmake make pkgconf-pkg-config git openssl-devel \
    krb5-devel krb5-workstation krb5-pkinit libcurl-devel libxml2-devel \
    openldap-devel cyrus-sasl-devel cyrus-sasl-gssapi
scl enable gcc-toolset-15 bash
```

Run the following in the compiler-enabled shell, from the repository root. Use that same root for all Linux commands in this guide:

```sh
git clone https://github.com/nomorefood/craft.git
cd craft
cmake -S source -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

CMake checks the compiler library and required Kerberos API. A compiler that accepts C++20 syntax but lacks the standard library facilities is insufficient. Package names and Toolset availability vary; select a supported Toolset meeting the minimum, following [Red Hat's Toolset instructions](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/developing_c_and_cpp_applications_in_rhel_9/assembly_additional-toolsets-for-development-rhel-9_developing-applications) and [support lifecycle](https://access.redhat.com/support/policy/updates/rhel-app-streams-life-cycle).

There is no CMake installation target. Install the three production executables manually; never install a test executable as `craft` or give it setuid permissions. Check `ldd build/craft build/craft-worker build/craft-maintain` for missing runtime libraries before installation.

The examples use `/usr/local/bin`, `/usr/local/libexec`, `/etc/craft` and `/run/craft`. To use other locations, set `CRAFT_LAUNCHER`, `CRAFT_WORKER`, `CRAFT_CONFIG_DIR` and `CRAFT_RUNTIME_DIR` to absolute paths during CMake configuration. These paths are compiled in; changing `CMAKE_INSTALL_PREFIX` alone does not change them. Update installation commands, Kerberos file references, tmpfiles and audit rules to match. Trusted paths cannot contain symlinks, including parent directories.

## Shared Linux installation

Install binaries and disabled example configuration as an administrator. On an existing installation, preserve the reviewed configuration and trust files instead of overwriting them with examples.

```sh
sudo install -d -o root -g root -m 0755 /usr/local/bin /usr/local/libexec /etc/craft
sudo install -o root -g root -m 0755 build/craft /usr/local/bin/craft
sudo install -o root -g root -m 0755 build/craft-worker /usr/local/libexec/craft-worker
sudo install -o root -g root -m 0755 build/craft-maintain /usr/local/bin/craft-maintain
sudo install -o root -g root -m 0644 source/config/config.example /etc/craft/config
sudo install -o root -g root -m 0644 source/config/krb5.conf.example /etc/craft/krb5.conf
```

Replace `/etc/craft/config` with the snippet for your selected mode, then edit the actual values. Keep `enabled=no` during setup. Preserve `root:root` ownership and mode 0644 after editing.

Pin the actual realm and KDC in `/etc/craft/krb5.conf`. Retain AES-only permitted enctypes. For modes 1-3, retain `pkinit_require_crl_checking=true`, `pkinit_eku_checking=kpKDC`, and the expected KDC DNS name in `pkinit_kdc_hostname`. Provision a KDC certificate supporting the configured identity and EKU checks. Maintain DNS resolution, time synchronization and network access to the pinned KDC, LDAP/GC and CES endpoints needed by your mode.

| File under `/etc/craft` | Required modes and purpose | Ownership and mode |
| --- | --- | --- |
| `config`, `krb5.conf` | All: acquisition policy and Kerberos/KDC configuration | `root:root`, 0644 |
| `kdc-trust.pem`, `kdc-crls.pem` | 1-3: approved KDC CA anchors and current chain CRLs | `root:root`, 0644 |
| `ca-trust.pem`, `ca-crls.pem` | 1 and 3: user-certificate CA chain and CRLs; mode 1 also validates the agent | `root:root`, 0644 |
| `submitter.keytab` | 1 and 2: AD service principal for LDAP/CES; 4: dedicated constrained-delegation broker | `root:craft`, 0640 |
| `agent.pem`, `agent.key` | 1: enrollment-agent certificate and matching unencrypted private key | `root:craft`, 0640 |
| `https-trust.pem` | 1: CES HTTPS CA trust | `root:craft`, 0640 |
| `https-crls.pem` | 1, optional: current CRLs covering every CA in the CES server chain | `root:craft`, 0640 |
| `https-client.pem`, `https-client.key` | 1 with mTLS: separate CES transport certificate and unencrypted key | `root:craft`, 0640 |

Use populated PEM bundles from your PKI; empty files are invalid. Include the required issuing/intermediate chain certificates and CRLs. The example `pkinit_pool` references `ca-trust.pem`; for mode 2 alone, omit the pool if unnecessary or point it at a root-controlled bundle of KDC intermediates. If users also supply home certificates, install their CA trust and CRLs. All trusted files and parent directories must be root-owned, not group/world-writable and not symlinks. Keep accepted issuers narrow.

Refresh CRLs independently before their next-update time. CRAFT does not download CRLs or intermediate certificates. When `https-crls.pem` is present, CES HTTPS revocation is enforced; without it, HTTPS checks chain and hostname but has no CRL/OCSP check. See [MIT PKINIT configuration](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html#pkinit-krb5-conf-options) for KDC trust settings.

For `craft-maintain` and applications using the cache, configure system `/etc/krb5.conf` for the same realm, KDC and AES policy. CRAFT acquisition uses its private configuration; maintenance renewal and ordinary applications use the system configuration. Protect included configuration and plugin paths too.

The host logging service must accept AUTHPRIV records at `/dev/log`; a bare container without this socket cannot acquire credentials. On auditd hosts, adjust [craft.audit.rules](config/craft.audit.rules) for installed paths, architecture and existing files, remove rules for secrets or optional programs not installed, then load them:

```sh
sudo install -o root -g root -m 0640 source/config/craft.audit.rules /etc/audit/rules.d/craft.rules
sudo augenrules --load
```

Confirm the rules loaded successfully. Configure retention, forwarding and alarms in the host logging/audit services. See [audit records and diagnostics](#audit-records-and-diagnostics).

## Shared privileged installation

**Modes 1, 2 and 4.** Add a dedicated service account, restricted caller group and private runtime directory after shared installation. Reuse existing correctly configured accounts/groups when upgrading.

```sh
sudo groupadd --system craft
sudo useradd --system --gid craft --home-dir /nonexistent \
    --shell /usr/sbin/nologin craft
sudo groupadd --system craft-users
sudo install -o root -g craft-users -m 0750 build/craft /usr/local/bin/craft
sudo install -o root -g root -m 0644 source/config/craft.tmpfiles.conf /etc/tmpfiles.d/craft.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/craft.conf
sudo usermod -aG craft-users alice
```

Use the host's actual `nologin` path. On non-systemd hosts, recreate `/run/craft` as `craft:craft` mode 0700 at each boot. Only the service account belongs to `craft`; approved callers join `craft-users` and normally need a new login. Keep the launcher mode 0750 until the mode's credentials and policy are ready.

After completing mode 1, 2 or 4 setup, set `enabled=yes` and enable the launcher:

```sh
sudo chmod 4750 /usr/local/bin/craft
```

Only the launcher is setuid; the worker and maintainer remain mode 0755. `nosuid` mounts or inherited `no_new_privs` prevent privileged acquisition. Invoke `craft` directly as the approved user. Removing setuid still permits a valid home pair in modes 1-3; mode 4 requires the broker.

## Mode 1 setup: Privileged certificate enrollment

1. Complete the shared Linux and privileged installations, leaving acquisition disabled.
2. Prepare the [AD CS template, agent, directory account and CES endpoint](#assumptions-and-windows-preparation). Enforce [enrollment-agent restrictions](../docs/03-Enrollment-Agent-Restrictions.md) on every relevant CA.
3. Install `submitter.keytab`, `agent.pem`/`agent.key` and `https-trust.pem` as `root:craft` mode 0640, plus the public user/agent and KDC trust/CRL bundles. For mTLS, also install `https-client.pem`/`https-client.key`.
4. Replace `/etc/craft/config` with actual values based on this snippet:

```ini
enabled=no
domain=domain.local
realm=DOMAIN.LOCAL
mechanism=enrollment
netbios=DOMAIN
service_principal=svc-linux-enroll@DOMAIN.LOCAL
template_oid=1.3.6.1.4.1.311.21.8.999.1
ces_url=https://ces.domain.local/IssuingCA_CES_Kerberos/service.svc/CES
ces_auth=negotiate
key_bits=3072
certificate_cn={user}
tgt_seconds=36000
renew_seconds=604800
require_full_tgt_lifetime=yes
cert_remaining_max_seconds=36000
cert_total_max_seconds=36000
minimum_interval_seconds=60
```

The CES URL and template OID are placeholders. `template_oid` is the template's `msPKI-Cert-Template-OID`, not its name. Configure `gc_url`/`gc_base_dn` when the defaults do not uniquely resolve users. Enable acquisition and setuid only when ready, then run the [enrollment acceptance checks](TESTING.md#live-acceptance-checklist) as an approved user with both home PEM files absent. Confirm CA refusal for prohibited recipients independently of CRAFT.

## Assumptions and Windows preparation

The following AD/PKI preparation applies to mode 1. The [CA provisioning helper](#windows-provisioning-helper) performs part of it; Linux does not install or configure Windows services.

### Directory identity

Provision a least-privilege AD service account and an AES keytab matching its exact `service_principal`. Both CES authentication modes require the keytab for LDAP/GSSAPI. The account needs directory read access; it must not administer the CA, templates or approved recipient group.

CRAFT resolves `sAMAccountName=<Linux username>` through the GC, with referrals disabled. `gc_url` defaults to `ldap://<domain>:3268` and `gc_base_dn` to the domain DN. Use a host with a working `ldap/hostname` SPN and a base yielding one intended account. Zero or multiple matches fail. The resolved UPN may use an alternate suffix; an absent UPN falls back to `<caller>@<domain>`. The Kerberos principal remains `<caller>@<realm>`, and the signed enrollment request identifies `NETBIOS\caller`.

### Enrollment agent and dedicated template

Provision `agent.pem` with Certificate Request Agent EKU `1.3.6.1.4.1.311.20.2.1`, its matching key, trusted CA chain and current CRLs. On the CA's **Enrollment Agents** tab, restrict the actual signing identity to one dedicated template and a small approved recipient group. Remove overlapping broad grants and exclude privileged accounts. The agent EKU and template Enroll permission do not define the recipient boundary.

Use a v2-or-later user template with these properties:

| Property | Required mode 1 profile |
| --- | --- |
| Identity | AD-built subject and exactly one UPN otherName SAN matching the resolved UPN; retain the CA-generated SID security extension for KDC strong mapping |
| EKUs | Smart Card Logon `1.3.6.1.4.1.311.20.2.2`, Client Authentication `1.3.6.1.5.5.7.3.2`, and PKINIT Client Authentication `1.3.6.1.5.2.3.4`; CRAFT requires all three |
| Constraints and usage | Explicit CA:FALSE without path length; digitalSignature; no keyCertSign/cRLSign; keyEncipherment is optional |
| Key and template | RSA key size at least the template minimum; template-information extension containing the configured OID |
| Issuance authorization | One authorized Certificate Request Agent signature, narrow enrollment ACLs and CA recipient restrictions |
| Validity | Currently valid with more than 60 seconds remaining; by default no more than ten hours total or remaining, including CA backdating |

The CA determines validity; the client caps are acceptance limits and do not change issued dates. Keep **Supply in the request** and CA-wide arbitrary SAN overrides disabled. The CN is cosmetic and may be overridden by the CA. Manager approval/pending requests, multiple signatures, hardware attestation and key archival are unsupported by this acquisition flow. Review [strong certificate mapping](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16) and the detailed [authorization checks](../docs/03-Enrollment-Agent-Restrictions.md).

### CES transport authentication

Use an initial-enrollment CES endpoint over verified HTTPS, with TLS 1.2 or later. The agent signature authorizes the EOBO request separately from transport authentication.

| Setting | Required preparation |
| --- | --- |
| `ces_auth=negotiate` | MIT Kerberos/SPNEGO-enabled libcurl, service keytab, `HTTP/ces-host` SPN and required CES-to-CA constrained delegation; require Kerberos and disable NTLM fallback at CES |
| `ces_auth=mtls` | Actual certificate-authenticated endpoint and separate HTTPS client pair mapped to the authorized submission account; retain the directory keytab |

CRAFT pins the endpoint and template locally; it does not query a Certificate Enrollment Policy Web Service. Username/password and SOAP UsernameToken authentication are unsupported. Redirects and proxy environment settings are ignored. The transport TGT lasts five minutes and is never published to the user. See [Microsoft CES configuration](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-certificate-enrollment-web-service).

## Mode 2 setup: Privileged credential linking

1. Complete shared Linux and privileged installation with acquisition disabled. Provision the service account's AES keytab as `root:craft` mode 0640.
2. Select a writable DC supporting NGC/Key Trust, with `msDS-KeyCredentialLink` in the schema and a trusted PKINIT KDC certificate. Pin that **same DC** in `/etc/craft/krb5.conf` and `kt_dc_url` to avoid replication delay.
3. Delegate ReadProperty/WriteProperty on **only `msDS-KeyCredentialLink`** over a reviewed OU of ordinary users or a single user. Follow [Key Trust delegation](../docs/04-Key-Credential-Link-Delegation.md) for the helper and denial tests. This write permits authentication as every account in scope; exclude privileged identities.
4. Replace `/etc/craft/config` with the actual values:

```ini
enabled=no
domain=domain.local
realm=DOMAIN.LOCAL
mechanism=key_trust
service_principal=svc-linux-enroll@DOMAIN.LOCAL
kt_dc_url=ldap://dc01.domain.local
key_bits=3072
tgt_seconds=36000
renew_seconds=604800
require_full_tgt_lifetime=yes
minimum_interval_seconds=60
```

Only `ldap://` is accepted; LDAP/GSSAPI supplies integrity and encryption with a minimum SASL SSF of 128. No user-certificate CA enrollment, template, agent or CES credentials are required. Retain KDC trust and CRLs and configure the intermediate pool as described in shared installation. The generated certificate carries the directory-authorized public key; review its [temporary issuer trust scope](SECURITY.md#key-trust-certificate-handling).

Enable acquisition and setuid when ready, then complete [Key Trust acceptance](TESTING.md#key-trust-acceptance-checks) with both home files absent. CRAFT adds and removes its exact value while preserving existing keys. Removal must succeed before credentials are published. Independent cleanup also attempts removal after acquisition failure or worker termination; continuing directory outages or host failure can leave a key requiring manual removal. Monitor CRITICAL logs and the target attribute after interruptions. Key Trust capability is provided by Windows Server 2016 or later, but verify the deployed KDC and MIT PKINIT freshness policy rather than relying on a domain-functional-level label.

## Mode 3 setup: Unprivileged Windows-exported certificate

1. Complete shared Linux installation with ordinary mode-0755 executables. No Linux service account, private service credentials, caller group, setuid bit or `/run/craft` is required.
2. On Windows, select a template permitting the intended domain user's direct enrollment and exportable software keys. Its certificate must meet the [supplied profile](#certificate-and-identity-checks) and KDC mapping policy. Run the [Windows helper](#request-a-home-certificate-on-windows) as that user without elevation:

```bat
.\scripts\Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate"
```

Transfer both exported `user.pem` and unencrypted `user.key` securely to Linux after the helper succeeds. Keep its tracking metadata on Windows. Install as the intended Linux user in that user's NSS home:

```sh
mkdir -p ~/.config/craft
chmod 0700 ~/.config/craft
install -m 0600 /path/to/transferred/user.pem ~/.config/craft/user.pem
install -m 0600 /path/to/transferred/user.key ~/.config/craft/user.key
```

The home, `.config` and `craft` directories must be caller-owned and not group/world-writable. Both files must be caller-owned regular files, nonempty, at most 1 MiB and have one hard link. Symlinks are refused at the home's final component and below it. The key must be unencrypted with no group/other permissions; the certificate must not be group/world-writable. Direct PFX loading, passphrase prompts, PKCS#11 and hardware-key backends are unsupported.

Replace `/etc/craft/config` with the actual values:

```ini
enabled=no
domain=domain.local
realm=DOMAIN.LOCAL
tgt_seconds=36000
renew_seconds=604800
require_full_tgt_lifetime=yes
```

Install the public user-certificate and KDC trust/CRL bundles, then set `enabled=yes` when ready. There is no `mechanism=home` value: the complete pair selects this path. Complete [home workflow acceptance](TESTING.md#home-workflow-acceptance-checks). Replace the pair before expiry; neither CRAFT nor `craft-maintain` renews or transfers it. An approved existing PEM pair can also be supplied without using the Windows helper.

### Certificate and identity checks

The supplied certificate must match the key, be non-CA, include digitalSignature without keyCertSign/cRLSign, and have Smart Card Logon or PKINIT Client Authentication EKU. It must contain exactly one well-formed UTF8String UPN otherName SAN, be currently valid with more than 60 seconds remaining, and pass CA chain/current CRL validation. basicConstraints may be absent; when present it must specify CA:FALSE without a path length.

Home mode performs no LDAP lookup or directory-UPN comparison. The KDC must map the certificate to `<Linux username>@<realm>`; CRAFT verifies that principal in the returned TGT. Alternate certificate UPN suffixes are permitted. Enrollment's template OID, all-three-EKU requirement and certificate validity caps do not apply. `certificate_cn` does not alter a supplied certificate.

## Mode 4 setup: Service tickets through constrained delegation

1. Complete shared Linux and privileged installation, leaving acquisition disabled.
2. Follow [broker-account constrained delegation](../docs/05-Constrained-Delegation.md) to register a dedicated broker SPN, enable protocol transition and authorize only the required target SPNs in AD. This mode needs neither user certificates nor directory write permission.
3. Install the broker AES keytab as `/etc/craft/submitter.keytab`, owned by `root:craft`, mode 0640. Pin the realm/KDC and AES policy in `/etc/craft/krb5.conf`. KDC certificate anchors, CRLs, PKINIT, LDAP and CES are not used by this mode.
4. Replace `/etc/craft/config` with reviewed values:

```ini
enabled=no
domain=domain.local
realm=DOMAIN.LOCAL
mechanism=constrained_delegation
service_principal=CRAFT/broker.domain.local@DOMAIN.LOCAL
service_spns=cifs/files.domain.local@DOMAIN.LOCAL HTTP/portal.domain.local@DOMAIN.LOCAL
service_ticket_seconds=36000
minimum_interval_seconds=60
```

`service_spns` is a whitespace-separated list of 1-32 unique, explicit `service/host@REALM` names in the configured realm. Ports are permitted in the host component. Wildcards, `krbtgt`, the broker principal and cross-realm targets are refused. Use the exact names that applications request and verify that the application accepts a cache containing service tickets without a TGT. Some clients require a TGT before attempting service authentication. Each name must also be authorized by the broker's AD delegation policy; local configuration cannot grant delegation.

`service_ticket_seconds` requests a maximum validity of 60-604800 seconds, default 36000. The private broker TGT requests at least ten minutes for S4U processing, or the service lifetime if longer, with no renewal. It stays in memory and does not change the exported service-ticket cap. The KDC can shorten service grants; mode 4 accepts them. `tgt_seconds`, `renew_seconds`, `require_full_tgt_lifetime` and certificate settings do not govern service-ticket validity. The final tickets may carry forwardable/forwarded flags required by S4U; no TGT, broker credential, proxy-cache metadata or evidence ticket is exported.

Stop existing maintainers and remove the old CRAFT cache when changing an installation from a TGT mode to service-only operation. Set `enabled=yes`, enable the setuid launcher and run the [mode 4 acceptance checks](TESTING.md#constrained-delegation-acceptance-checks). Existing tickets remain valid until their domain-enforced expiry. Home PEM files are ignored even if present, partial or invalid. Missing/denied targets fail the entire acquisition and preserve the previous cache.

## Configuration reference

CRAFT configuration uses case-sensitive `key=value` entries and full-line `#` comments. Empty values, duplicate/unknown keys and invalid numeric values are refused. Inline `#` text is part of the value, so put comments on separate lines. Omit optional settings to use their defaults. [config.example](config/config.example) documents the disabled enrollment example.

| Setting | Default or requirement | Applies to |
| --- | --- | --- |
| `enabled` | Required; exactly `yes` enables acquisition, `no` disables it | All |
| `domain` | Required lowercase DNS domain, e.g. `domain.local` | All |
| `realm` | Required uppercase DNS realm, e.g. `DOMAIN.LOCAL` | All |
| `tgt_seconds` | `36000`; integer 60–604800 | 1-3 |
| `renew_seconds` | `604800`; 0 disables renewal, otherwise greater than `tgt_seconds`, at most 604800 | 1-3 |
| `require_full_tgt_lifetime` | `yes`; `no` accepts shorter initial/renewal grants with a warning | 1-3 |
| `mechanism` | `enrollment`, `key_trust` or `constrained_delegation`; default `enrollment`; mode 4 overrides home certificates | 1, 2 and 4 |
| `service_principal` | Required exact AD principal matching `submitter.keytab` | 1, 2 and 4 |
| `key_bits` | `3072`; accepts 2048, 3072 or 4096; satisfy the enrollment template minimum | Generated identities in 1 and 2 |
| `service_spns` | Required whitespace-separated exact service/host@REALM list, 1-32 entries | 4 |
| `service_ticket_seconds` | 36000; 60-604800; shorter KDC grants accepted | 4 |
| `certificate_cn` | `{user}`; tokens `{user}`, directory `{upn}`, `{domain}`; expansion 1–64 printable ASCII characters without braces | Generated identities in 1 and 2 |
| `minimum_interval_seconds` | `60`; integer 30–86400; failed attempts also count | 1, 2 and 4 |
| `netbios` | Required uppercase AD NetBIOS domain, at most 15 characters | 1 |
| `template_oid` | Required actual `msPKI-Cert-Template-OID` | 1 |
| `ces_url` | Required plain `https://host[:port]/path`, without credentials, query or fragment | 1 |
| `ces_auth` | Required `negotiate` or `mtls` | 1 |
| `gc_url` | `ldap://<domain>:3268`; protected by LDAP/GSSAPI | 1 |
| `gc_base_dn` | Domain DN, e.g. `DC=domain,DC=local` | 1 |
| `cert_remaining_max_seconds` | `36000`; integer 60–86400, no greater than total cap | 1 |
| `cert_total_max_seconds` | `36000`; integer 60–86400, includes backdating | 1 |
| `kt_dc_url` | Required `ldap://` URL naming the same writable DC as the KDC | 2 |

Shared numeric and length limits are parsed even when a setting is unused by the selected mode. Omit irrelevant settings rather than leaving invalid placeholders.

Ticket validity and certificate validity are separate. Modes 1-3 request ten hours initially and seven days of renewal by default, while the KDC controls the actual grant. Certificate/key lifetime can constrain initial PKINIT validity. Strict policy compares grants with a five-second tolerance and refuses shortened or excessive grants before replacing the cache. Setting `require_full_tgt_lifetime=no` permits shorter grants; it does not permit wrong principals, flags, non-AES encryption or excessive lifetimes. Use policy appropriate to the domain rather than increasing certificate caps to accommodate an unintended template. See [RFC 4556 ticket lifetime rules](https://www.rfc-editor.org/rfc/rfc4556#section-3.2.3).

The accepted Kerberos encryption types are `aes256-cts-hmac-sha1-96` (18) and `aes128-cts-hmac-sha1-96` (17), in that preference order. Configure suitable AES keys/policy on the DC, `krbtgt` and service account. Session and outer-ticket encryption are checked separately and may use different AES sizes.

## Use

Run as the intended non-root user and stop the script if acquisition fails:

```sh
cache=$(/usr/local/bin/craft) || exit "$?"
export KRB5CCNAME="$cache"
klist -ef -c "$KRB5CCNAME"
# Run the Kerberos-aware application from this shell.
```

Stdout is the `FILE:` cache name on success; diagnostics use stderr and the system log. `craft` exits 0 on success and 1 on failure. It cannot modify the parent shell's environment. CMake also generates an optional ordinary `build/with-craft` wrapper; `./build/with-craft klist` obtains a fresh cache and runs the command with it selected.

The fixed NSS-home `.krb5cc_craft` is caller-owned mode 0600 and contains the user TGT in modes 1-3 or only configured service tickets in mode 4, together with their session keys, without the certificate/private key. Success replaces it atomically. Acquisition/validation failures preserve the current cache. In modes 1-3, applications obtain service tickets using their system Kerberos configuration and remain subject to the user's permissions. Cache and supplied PEM files persist after exit or expiry; protect them from backups, sync, indexing and other users. Generated enrollment keys/certificates are released after authentication; CA issuance records remain.

### Long-running jobs

Start once from the job script as the approved user:

```sh
job_pid=$$
cache=$(/usr/local/bin/craft-maintain --watch-pid "$job_pid") || exit "$?"
export KRB5CCNAME="$cache"
```

Startup returns when usable credentials and detached maintenance are ready. Renewal uses the cache alone. Fresh authentication invokes `craft` with the same mode selection. Full ten-hour/seven-day grants normally renew near hour eight and authenticate afresh near day six; actual ticket times set the schedule. Renewal retains usable service tickets; fresh acquisition replaces the cache. Applications must reload refreshed credentials when authenticating again.

For mode 4, maintenance refreshes the whole batch through `craft` when any service ticket reaches its expiry margin. It never renews a user TGT. The broker and KDC must be available for each refresh; keep the acquisition interval below the refresh interval implied by actual grants. Changing the configured SPN list takes effect on fresh acquisition.

Install the maintainer without setuid/setgid. It uses system `/etc/krb5.conf` and ignores user Kerberos overrides for renewal. The watched PID must belong to the caller and last for the job: keep the shell alive, `exec` the workload or watch its controller. Linux pidfds are used when available, with `/proc` monitoring otherwise. The scheduler must retain background processes in the job cgroup. Home refresh works under `no_new_privs`; privileged refresh needs later setuid calls. Optional `--max-duration 21d` adds a cutoff; durations accept integer seconds or `s`, `m`, `h`, `d` suffixes, up to 365 days.

Inspect as the same user with the original job PID:

```sh
/usr/local/bin/craft-maintain --status --watch-pid "$job_pid"
klist -ef -c "$KRB5CCNAME"
```

Status reports `ready`, `retrying`, `expired`, `stopped` or `failed`, `ticket_kind` (`tgt` or `service`), `ticket_expires` and `renew_until` as Unix seconds, `maintainer_pid`, `next_check` and `last_error`. A successful status read does not prove credential health; `next_check=0` indicates no further checks. Private `.krb5cc_craft.maintain.<PID>.status` files remain after exit and are pruned by a later maintainer once a week old. Jobs for one UID share the cache and fresh-acquisition cooldown.

Renewal failures preserve credentials and retry without immediate fresh authentication. Missing/expired TGTs, nonextendible tickets near expiry and renewal-window rollover require fresh acquisition; failures share a cooldown from one minute to one hour. Later failures do not terminate the job. Keep required CRLs, service credentials and supplied certificate pairs current.

## Audit records and diagnostics

Read AUTHPRIV records with administrator access:

```sh
sudo journalctl -t craft -t craft-worker -t craft-maintain
```

On other logging systems, inspect the configured AUTHPRIV destination. `craft` records request start, failure and completed cache publication; `craft-worker` records TGT issuance with `certificate_source=home|enrollment|key_trust`, mode 4 issuance with `mechanism=constrained_delegation` and the service count, and Key Trust add/remove/cleanup failures; `craft-maintain` records startup, stop, renewal and fresh acquisition. The worker's `request=` matches the launcher's PID, and `worker=` identifies the directory-operation process. Records contain no key, ticket or certificate bytes.

Logging failure blocks startup, credential release and renewal publication. A launcher failure to log its completed publication can occur after the cache was replaced; inspect the cache and logs when diagnosing such a failure. The `/dev/log` check confirms local submission, not durable retention or forwarding.

Callers receive a failure summary and a log identity/PID for system, server or library details. Correctable caller-file and rate-limit errors are shown directly. `craft-maintain --status` uses the same diagnostic policy.

| Symptom | Administrator checks |
| --- | --- |
| Missing audit socket or audit submission failure | Host logging service, `/dev/log` and permissions; do not substitute a dummy logger on a deployed host |
| No home pair on an ordinary installation | Supply both PEM files, or deliberately complete the privileged installation |
| Home-file rejection | NSS home, owner/mode, symlinks, hard links, PEM format, matching key and certificate profile |
| Trust or PKINIT rejection | Clock, current CRLs, CA/KDC chains, PKINIT plugin, pinned KDC identity/EKU, mapping and actual ticket policy |
| LDAP/GSSAPI failure | SASL GSSAPI plugin, DNS/SPN, exact service principal, AES keytab and writable DC/GC access |
| CES or certificate-profile failure | Endpoint/authentication, HTTPS trust/optional CRLs, CA restrictions, template OID, EKUs, UPN/SID and total validity including backdating |
| Rate limit or concurrent acquisition | Wait for the configured interval; modes 1, 2 and 4 allow one attempt per UID at a time, including failures |
| CRITICAL Key Trust cleanup failure | Inspect the named object and remove only the residual CRAFT value; retain legitimate keys and investigate the outage/delegation |
| S4U2Self/S4U2Proxy rejection | Broker SPN/keytab, protocol transition, exact AD target SPNs, target AES keys, Protected Users and Account is sensitive and cannot be delegated |
| Maintenance fails to refresh | Status/logs, system Kerberos settings, watched PID/cgroup, KDC reachability, credential expiry and permitted setuid refresh |

Do not resolve rejection by weakening certificate mapping, TLS verification, required CRLs or authorization scope. See [security and operational disable](SECURITY.md#immediate-disable) and the [acceptance checks](TESTING.md).

## Request a home certificate on Windows

[`Request-CRAFT-Certificate.cmd`](../scripts/Request-CRAFT-Certificate.cmd) runs as the signed-in domain user without elevation. It requires Windows PowerShell 5.1, .NET Framework 4.7.2 or newer, the Windows PKI module, and access to AD/enterprise enrollment services. RSAT and OpenSSL are unnecessary. Use the template's internal name or OID; Windows enrollment policy selects an eligible CA. The account must map to the intended Linux username/realm.

Run from the repository root with a dedicated local destination directory:

```bat
.\scripts\Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate" /WhatIf
.\scripts\Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate"
```

| Option | Behavior |
| --- | --- |
| `/WhatIf` | Preview without enrollment or export changes |
| `/RenewBeforeDays N` | Override the default one-calendar-month renewal window; accepts 0–3650 days, including fractional days; 0 replaces expired certificates only |
| `/DeleteAfterExport` | After successful export/reuse, remove the Windows-store certificate; default off; PEM files remain |

The helper exports `user.pem`, matching unencrypted PKCS#8 `user.key`, and private `.craft-certificate.json` tracking metadata. New outputs permit only the caller, SYSTEM and local administrators. It checks the supplied-certificate profile before publication; Linux separately checks trust, revocation, permissions and KDC mapping. Outside the renewal window it reuses a valid managed pair. It refuses incomplete, modified, unmanaged or different-template output.

Renewal stages a replacement and preserves the old pair on enrollment/export failure. Successful renewal removes the old Windows-store certificate. Private keys are deleted only when provider/container metadata proves no other current-user certificate shares the container; shared or unidentified containers remain. Deletion is local and does not revoke certificates or tickets. Failed requested store deletions remain queued in metadata for the next invocation, even if the retry omits `/DeleteAfterExport`; usable exports remain.

After interruption, leave `.craft-certificate.transaction.json` and staging backups in place so the next run can recover under the export lock. Changed or unsafe recovery files require review. Individual file replacement is atomic; transfer the pair only after a successful helper return. Remove unneeded transfer copies. Schedule repeat helper runs and secure transfers separately; it does not schedule itself.

Exit codes are 0 for success/reuse/preview, 1 for failure, 2 for pending approval and 64 for invalid CMD arguments. A pending request stays in the Windows request store and preserves existing exports; retrieve approval with Windows enrollment tools. If AppLocker/WDAC puts the unsigned CMD wrapper in Constrained Language Mode, use a trusted signed `.ps1` copy as its help describes, with `-TemplateName`, `-Destination` and PowerShell-style options. Keep the host's script policy intact.

## Windows provisioning helper

[`Configure-CRAFT-CA.ps1`](../scripts/Configure-CRAFT-CA.ps1) is an optional mode 1 lab helper. It changes AD accounts, template permissions and CA publication, exports credentials, and writes disabled Linux configuration. It does not configure CES, HTTP SPNs/delegation, CA enrollment-agent restrictions or Linux installation. It verifies the required narrow agent/template/recipient restrictions before publication/export; configure those restrictions first.

Inspect help and preview from the repository root on an authorized Windows administration host:

```powershell
Get-Help .\scripts\Configure-CRAFT-CA.ps1 -Full
$exportPassword = Read-Host 'Agent PFX export password' -AsSecureString
.\scripts\Configure-CRAFT-CA.ps1 -AllowedTargetGroup 'CRAFT Approved Users' `
    -CesUrl 'https://ces.domain.local/IssuingCA_CES_Kerberos/service.svc/CES' `
    -ExportPassword $exportPassword -WhatIf
```

The helper requires the ActiveDirectory module, `ktpass`, `certreq`, `certutil` and authorized directory/CA access. Supply an existing narrowly scoped security group, actual CES URL and secure export password; specify CA/DC when discovery is ambiguous. `ValidityHours` accepts 1–24, `KeySize` 2048/3072/4096. It exports matching `key_bits`, ticket validity capped at ten hours and certificate caps matching `ValidityHours`; verify actual backdating separately.

It uses the same named account for the keytab and agent signing certificate; provision separate identities manually if required. Automatic agent export requires running as that agent, otherwise supply its PFX separately. `ktpass` resets the account password; an existing `submitter.keytab` stops the helper before changes, so plan rotation separately. Convert DER/PFX exports to the required PEM bundles and unencrypted operational key using approved PKI tools, protect export copies, and provision any missing chain certificates/CRLs. Complete live acceptance before setting `enabled=yes`.

## License

Source code, scripts, configuration examples and documentation are licensed under [GNU GPL version 3 only](../LICENSE) (`GPL-3.0-only`).
