# CRAFT Security Review Notes

## Trust Decision

Resolving a Unix username against Active Directory delegates authentication of that AD account to this host. User passwords and AD MFA are not checked by the helper. A software key carrying Smart Card Logon EKU is not evidence of hardware custody or a second factor.

Restrict the enrollment agent at the CA to a dedicated template and approved recipient group. Local policy checks are defense in depth, not a replacement for CA restrictions. Do not authorize privileged AD administrators in the initial deployment. Protect and audit UID/name lifecycle, NSS providers, root accounts and the service account.

See [Enrollment Agent Restrictions](../docs/03-Enrollment-Agent-Restrictions.md) for CA policy, privileged-account exclusion, credential custody, and live denial tests.

## Lifetime and Encryption Policy

The default ten-hour initial user TGT with seven-day renewal matches the most permissive DISA STIG guidance for domain controllers. A ten-hour certificate does not revoke an already-issued ticket, and destroying its private key does not destroy a cached TGT. A stolen mode-0600 cache still carries an independent session key. Do not treat certificate expiry, local deletion, or changing a file permission as ticket revocation.

`craft-maintain` renews cached tickets, obtains fresh credentials near the absolute renewal deadline, and stops with its watched job. It retains no user certificate/key and leaves the shared cache in place. Refresh failures preserve the cache; enrollment retries share backoff.

The worker does not forge or extend a KDC-issued ticket. RFC 4556 key/certificate-lifetime rules bind the initial ticket to the certificate validity. Strict mode rejects shortened initial grants and shortened renewable windows. AES128/256 checks cover session and outer ticket encryption, but do not compensate for excessive validity or host compromise.

Manage trusted NSS and account lifecycle centrally so that Linux usernames strictly match their corresponding Active Directory sAMAccountName. The directory-resolved UPN is checked against the issued certificate. The CA supplies the certificate SID, and the domain controller enforces certificate-to-account mapping. A custom CSR CN cannot change the authenticated identity.

## Privilege Separation

`craft` is the only intended setuid executable. It uses the real UID, accepts no arguments, clears the environment, opens a fixed root-controlled worker executable, and drops every real/effective/saved UID/GID before processing the returned cache or opening the caller's home. The worker runs under a dedicated non-root account; neither program invokes a shell. Credentials travel from worker to parent through a pipe; user keys use sealed memfd objects.

Run `craft-maintain` without setuid/setgid. It uses system Kerberos configuration, invokes the fixed `craft` launcher, and coordinates cache publication through private locks. Watched PIDs must belong to the caller; status files are private.

Only the service account should belong to the `craft` service group. The separately named `craft-users` group controls who may execute the launcher, in addition to Active Directory user account validation and runtime UID revalidation. Never give ordinary users the ability to run arbitrary commands as the service account.

## Temporary User Credentials

CRAFT keeps the issued user certificate and its private key in process memory and temporary memory-backed files for PKINIT, releasing them when the operation ends. It does not export a persistent user certificate/key file or install a certificate-store entry. The CA may retain issuance and audit records, and client cleanup does not revoke the certificate. The separate user ticket cache persists after CRAFT exits. Memory can reach swap or be captured by privileged host access; ephemeral storage is not a guarantee of secure erasure.

## Implemented Controls

- Dynamic UPN resolution through the Active Directory Global Catalog plus real-UID/NSS revalidation, fixed endpoint/template from root-owned files, no caller-supplied target identity or output path.
- No trusted-path symlinks; root ownership and parent write-permission checks; verified executable opened before privilege drop and launched with fexecve.
- Parent writes as caller, unique mode-0600 staging file, atomic fixed-name replacement, no target-symlink following.
- HTTPS peer/name verification, no redirects or proxy environment, no explicitly enabled Basic/NTLM authentication. Directory access uses the separately provisioned keytab over LDAP/GSSAPI in both CES modes.
- Agent signature/key/EKU/trust validation; returned certificate key/UPN/template/EKU/lifetime/trust/CRL validation.
- PKINIT certificate/private key and pinned KDC trust; rejecting password prompter; explicit TGT flags, principal, AES session/envelope and actual lifetime validation.
- Bounded network payloads, forbidden XML DTD/entity declarations, per-user issuance lock/interval, execution deadlines, CPU/address-space limits, no core dumps and non-dumpable processes.
- No private key or TGT printed in diagnostics. The stdout pipe is credentials; the launcher's stdout is only the cache name.

## Not Claimed

This is not independently audited, hardened against every local kernel/NSS/library attack, fuzz-tested, or validated against a live AD CS installation. There is no seccomp profile, SELinux/AppArmor policy, hardware key backend, remote authorization service, enrollment cancellation, cache collection, global issuance quota, interactive approval, or pin verification. Sensitive memory is not mlocked; memfd and normal memory may be swapped. Root can inspect the machine and steal or misuse credentials. The dedicated service account is also a high-value identity because it can read the enrollment-agent key.

The HTTPS path validates certificate chain and hostname but does not implement independent HTTPS-server revocation/OCSP checking. CA/user certificates and PKINIT KDC certificates have separate configured CRL requirements. Establish a suitable CES TLS lifecycle and revocation policy for your environment before production use.

The Kerberos configuration is administrator-controlled and can reference further files/plugins; those must be protected as well. Dynamic libraries, NSS modules, Kerberos preauth plugins, OpenSSL configuration/providers and the OS trust boundary must remain administrator-controlled. Do not add user-writable library paths or config includes. Inspect the rebuilt executable's dynamic dependencies before installation.

The exact returned user UPN and template are checked in application code after certificate verification. Pinning the actual issuing CA separately from the configured trust-chain files is not implemented. Keep the accepted CA set narrow and review any alternate strong mappings in AD that could conflict with intended identity selection.

## Required Live-Lab Checks

Follow [TESTING.md](TESTING.md). A successful build or synthetic cryptographic test does not establish interoperability with your CES endpoint, template policy, transport account, DC certificate, current strong mapping, or PKINIT plugin. Do not “fix” a rejection by disabling TLS validation, CRLs, strong mapping or CA-side authorization.

## Immediate Disable

Remove the launcher's setuid/execute permission and set `enabled=no` to disable fresh enrollment. Stop renewal by sending SIGTERM to active maintainers' recorded `maintainer_pid`. Revoke affected enrollment-agent/transport credentials if compromise is suspected. Issued tickets can remain valid until expiry; deleting a cache is not revocation. Review CA/CES/KDC/AUTHPRIV logs and follow your incident-response process.
