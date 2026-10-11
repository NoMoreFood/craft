# CRAFT Security Review Notes

## Trust Decision

CRAFT supports [mode 1 privileged enrollment](README.md#mode-1-setup-privileged-certificate-enrollment), [mode 2 privileged credential linking](README.md#mode-2-setup-privileged-credential-linking), and [mode 3 unprivileged Windows-exported certificate](README.md#mode-3-setup-unprivileged-windows-exported-certificate). A supplied home pair takes priority; only an absent pair selects the configured privileged mechanism.

CRAFT prioritizes a caller-owned certificate/key pair in the NSS home. Home mode runs all certificate and Kerberos work as the caller, without directory lookup, enrollment authority or service credentials. The KDC must map the certificate to the fixed `<Linux username>@<realm>` principal, and CRAFT verifies that principal in the returned TGT. A partial or invalid pair is an error, not permission to enroll.

In enrollment mode, resolving a Unix username against Active Directory delegates authentication of that AD account to this host. User passwords and AD MFA are not checked by the helper. A software key carrying Smart Card Logon EKU is not evidence of hardware custody or a second factor.

Restrict the enrollment agent at the CA to a dedicated template and approved recipient group. Local policy checks are defense in depth, not a replacement for CA restrictions. Do not authorize privileged AD administrators in the initial deployment. Protect and audit UID/name lifecycle, NSS providers, root accounts and the service account.

In Key Trust mode (`mechanism=key_trust`), the service account writes a temporary NGC key to the caller's `msDS-KeyCredentialLink`, authenticates with Key Trust PKINIT, and removes the key. Writing that attribute on an account is equivalent to authenticating as it; the delegated write scope is the authorization boundary, and no user-certificate CA enrollment, enrollment agent or user template is involved. Delegate only ReadProperty/WriteProperty on that one attribute over a dedicated OU of ordinary users, keep privileged accounts out of that scope, and keep the service account unable to rewrite its own delegation. Successful cache publication requires removal of the temporary key. Independent cleanup also runs after acquisition failure or worker termination, but directory unavailability or host failure can leave a residual key. Failed cleanup logs a CRITICAL AUTHPRIV event when it can run; the key remains a standing credential until cleared. The client certificate carries the public key for PKINIT; the registered directory key authorizes the user. KDC certificate trust and CRLs are still required.

See [Enrollment Agent Restrictions](../docs/03-Enrollment-Agent-Restrictions.md) for CA policy and [Key Trust Delegation](../docs/04-Key-Credential-Link-Delegation.md) for the `msDS-KeyCredentialLink` authorization boundary, privileged-account exclusion, credential custody, and live denial tests.

## Key Trust Certificate Handling

In Key Trust mode, Active Directory authorizes the client's public key through `msDS-KeyCredentialLink`. The short-lived client certificate carries that public key and the resolved UPN for PKINIT; an enterprise user-certificate CA chain does not authorize the user. Directory delegation and KDC certificate validation are separate trust decisions.

CRAFT creates a temporary self-signed local issuer with `CA:TRUE` to sign the client certificate for the MIT Kerberos PKINIT plugin. The issuer signs only this attempt's client certificate, and its private key is released after signing. Neither certificate is enrolled with AD CS, and the issuer is not installed in the OS or Active Directory trust stores.

MIT uses the same anchor set to build the outgoing client certificate chain and validate the KDC certificate. For each Key Trust request, CRAFT appends the temporary issuer to an in-memory copy of `kdc-trust.pem` and passes the combined bundle as [`X509_anchors`](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html#pkinit-krb5-conf-options). The configured file remains unchanged, but the temporary issuer is also a KDC-validation anchor for that request. KDC identity, EKU and CRL checks remain governed by `krb5.conf`; review this per-request anchor scope under the deployment's PKI trust policy.

## Lifetime and Encryption Policy

The default ten-hour initial user TGT with seven-day renewal matches the most permissive DISA STIG guidance for domain controllers. A ten-hour certificate does not revoke an already-issued ticket, and destroying its private key does not destroy a cached TGT. A stolen mode-0600 cache still carries an independent session key. Do not treat certificate expiry, local deletion, or changing a file permission as ticket revocation.

`craft-maintain` renews cached tickets, obtains fresh credentials near the absolute renewal deadline, and stops with its watched job. It retains no parsed user certificate/key between operations; supplied home files remain under the user's control, and the shared cache stays in place. Refresh failures preserve the cache; fresh-acquisition retries share backoff across modes.

The worker does not forge or extend a KDC-issued ticket. RFC 4556 key/certificate-lifetime rules bind the initial ticket to the certificate validity. Strict mode rejects shortened initial grants and shortened renewable windows. AES128/256 checks cover session and outer ticket encryption, but do not compensate for excessive validity or host compromise.

Manage trusted NSS and account lifecycle centrally so that Linux usernames strictly match their corresponding Active Directory sAMAccountName. Enrollment and credential linking check their certificate UPN against the directory-resolved UPN. Home mode requires a well-formed UPN SAN and relies on KDC mapping rather than an LDAP comparison. The CA supplies the certificate SID, and the domain controller enforces certificate-to-account mapping. A custom CSR CN cannot change the authenticated identity.

## Privilege Separation

A home-only installation uses ordinary mode-0755 `craft`, `craft-worker` and optional `craft-maintain` executables. Public `/etc/craft` configuration, trust anchors and CRLs are root-controlled and readable by callers. No service account, keytab, LDAP, enrollment agent, CES or `/run/craft` is required. The worker uses the caller's filesystem permissions to open `~/.config/craft/user.pem` and `user.key` and performs validation and PKINIT under that UID.

A privileged installation for mode 1 or 2 makes only `craft` setuid. It checks the home pair using a permanently unprivileged caller worker. The parent reads only a one-byte selection result while elevated; it drops all real/effective/saved IDs before reading credential bytes or publishing the cache. Only an absent pair starts the dedicated service-account worker. All paths clear inherited environment, execute a fixed root-controlled worker through `fexecve`, and process certificates and Kerberos outside root.

Only the service account belongs to `craft`. Private agent keys, keytabs and transport credentials remain `root:craft` mode 0640; public files use `root:root` mode 0644 in a root-owned mode-0755 directory. `craft-users` controls execution of the restricted launcher for modes 1 and 2. Never grant ordinary users the service identity or private enrollment files. A home-only deployment does not require that group.

`craft-maintain` runs without setuid/setgid, uses system Kerberos configuration and invokes the fixed `craft` entry point for fresh authentication. Home refresh works under `no_new_privs`; both privileged mechanisms require permitted setuid elevation. Watched PIDs belong to the caller, and cache/status locks are private.

## User Credential Storage

Supplied home certificates and keys persist until the user replaces or removes them. CRAFT releases its parsed objects and sealed PKINIT memory files after each operation, and does not renew or delete the source pair. These files provide a continuing authentication credential while the certificate is accepted by the KDC. Protect them separately from the cache.

Enrollment generates temporary user certificate/key material and does not export a persistent user PEM/PFX or store entry. CA issuance/audit records remain independently. Credential linking generates a local identity and adds a temporary directory key; failed cleanup can leave that key usable until removed. All modes leave the ticket cache after exit. Memory and memory files can reach swap or privileged host capture; ephemeral processing is not secure erasure. Certificate expiry, private-key deletion and cache removal do not revoke an issued TGT.

## Implemented Controls

- Real-UID/NSS revalidation in all modes; enrollment resolves UPN through the Active Directory Global Catalog, fixed endpoint/template from root-owned files, no caller-supplied target identity or output path.
- No trusted-path symlinks; root ownership and parent write-permission checks; verified executable opened before privilege drop and launched with fexecve.
- Parent writes as caller, unique mode-0600 staging file, atomic fixed-name replacement, no target-symlink following.
- HTTPS peer/name verification, no redirects or proxy environment, no explicitly enabled Basic/NTLM authentication. Directory access uses the separately provisioned keytab over LDAP/GSSAPI in both CES modes.
- Home files: fixed NSS paths, caller ownership, safe directories, private key permissions, regular files, no symlinks/extra hard links and bounded reads.
- CA-issued certificate modes (1 and 3): matching key, non-CA/logon usage, current certificate validity, CA trust and CRLs. Enrollment additionally checks agent authorization profile, directory UPN, template and short validity.
- Key Trust: integrity/confidentiality-protected GSSAPI LDAP bind with a minimum SASL SSF of 128 to the configured writable DC, single-value add that preserves other key credentials, directory-UPN-checked PKINIT certificate carrying the linked public key, and independent cleanup attempts on success, acquisition failure and worker termination. Successful publication requires removal; unavailable directory or host failure can leave a residual key, reported with a CRITICAL log when cleanup runs and fails.
- PKINIT certificate/private key and KDC trust anchors, including [Key Trust's temporary issuer](#key-trust-certificate-handling); rejecting password prompter; explicit TGT flags, principal, AES session/envelope and actual lifetime validation.
- Bounded network payloads, forbidden XML DTD/entity declarations, per-user acquisition lock/interval for modes 1 and 2, execution deadlines, CPU/address-space limits, no core dumps and non-dumpable processes.
- Audit records for each request, issuance, Key Trust directory change, publication, renewal and maintainer start and stop, submitted to the host logging service; an operation stops when its record is not taken. Records are bounded printable ASCII, so remote or library text cannot forge one.
- Callers see a summary of a failure; system paths, configuration, server and library messages go only to the audit log.
- No private key or TGT printed in diagnostics. The home worker first sends a selection byte; subsequent stdout pipe data is credentials; the launcher's stdout is only the cache name.

## Not Claimed

This is not independently audited, hardened against every local kernel/NSS/library attack, or validated for every AD CS, Key Trust and KDC deployment. Fuzzing covers CRAFT's own parsers as [TESTING.md](TESTING.md#fuzz-testing) records, not the libraries beneath them or an installed system. Audit submission is confirmed only as far as the local logging socket; durable storage and forwarding are the host's. There is no seccomp profile, SELinux/AppArmor policy, hardware key backend, remote authorization service, enrollment cancellation, cache collection, global issuance quota, interactive approval, or pin verification. Sensitive memory is not mlocked; memfd and normal memory may be swapped. Root can inspect the machine and steal or misuse credentials. The dedicated service account is also a high-value identity because it can read the enrollment-agent key.

The HTTPS path validates certificate chain and hostname but does not implement independent HTTPS-server revocation/OCSP checking. CA/user certificates and PKINIT KDC certificates have separate configured CRL requirements. Establish a suitable CES TLS lifecycle and revocation policy for your environment before production use.

The Kerberos configuration is administrator-controlled and can reference further files/plugins; those must be protected as well. Dynamic libraries, NSS modules, Kerberos preauth plugins, OpenSSL configuration/providers and the OS trust boundary must remain administrator-controlled. Do not add user-writable library paths or config includes. Inspect the rebuilt executable's dynamic dependencies before installation.

Enrollment checks the returned user UPN and template after certificate verification. Home mode accepts ordinary templates and validity periods, requires Smart Card Logon or PKINIT Client Authentication EKU, and relies on the KDC to map the certificate to the requested caller principal. Pinning the actual issuing CA separately from the configured trust-chain files is not implemented. Keep the accepted CA set narrow and review any alternate strong mappings in AD that could conflict with intended identity selection.

## Required Live-Lab Checks

Follow [TESTING.md](TESTING.md). A successful build or synthetic cryptographic test does not establish interoperability with your CES endpoint, template policy, transport account, DC certificate, current strong mapping, or PKINIT plugin. Do not “fix” a rejection by disabling TLS validation, CRLs, strong mapping or CA-side authorization.

## Immediate Disable

Set `enabled=no` or remove execute permission to disable fresh acquisition through every path. Removing only the setuid bit disables both privileged fallbacks; a valid home pair can still authenticate. Stop renewal by sending SIGTERM to active maintainers' recorded `maintainer_pid`. Revoke affected enrollment-agent/transport credentials if compromise is suspected. For Key Trust, revoke the delegation (`Grant-CRAFTKeyCredentialLink.ps1 -Remove`), rotate `submitter.keytab`, and clear any residual `msDS-KeyCredentialLink` values on affected accounts. Issued tickets can remain valid until expiry; deleting a cache, clearing a key credential or rotating a keytab is not ticket revocation. Review CA/CES/KDC/directory/AUTHPRIV logs and follow your incident-response process.
