# CRAFT security and operations

Review these boundaries before enabling an installation. The host's authority differs by mode; local CRAFT checks do not replace CA authorization, AD delegation or KDC account mapping.

## Trust decision

| Mode | Authority on the Linux host | Required external control |
| --- | --- | --- |
| Enrollment Agent | Service keytab and enrollment-agent private key can obtain user certificates | CA restrictions on the actual signer, template and approved recipients |
| Key Trust | Service keytab can write public keys and authenticate as targets in its delegated scope | ReadProperty/WriteProperty on only `msDS-KeyCredentialLink` over reviewed ordinary users |
| BYOC | Each user holds a reusable certificate and private key | Authorized certificate issuance, revocation and KDC mapping to the fixed caller principal |
| Constrained Delegation | Broker keytab can impersonate delegable users to approved services | Protocol transition and exact `msDS-AllowedToDelegateTo` target SPNs on a dedicated broker |

The administrator's ordered `modes` list authorizes every acquisition path. Reported acquisition failures, including invalid home credentials, may fall through to the next listed mode. Only `modes=constrained_delegation` by itself guarantees service-ticket-only operation; enabling a certificate mode also permits a TGT. Invalid policy, worker interruption, unconfirmed directory cleanup and publication failures stop the request. Broker modes share one account/keytab, so review their combined authority. All modes request `<Linux username>@<realm>` and validate the returned credentials. Constrained Delegation publishes only explicitly configured same-realm services after every target succeeds; no user or broker TGT, S4U2Self evidence or proxy metadata is exported. Enrollment Agent and Key Trust resolve the directory UPN; BYOC relies on KDC mapping without LDAP. Keep Linux UID/name assignments and NSS providers under administrator control.

CRAFT does not check the user's AD password, perform an MFA challenge or establish completion of MFA. Software keys and Smart Card Logon EKU do not establish hardware custody or a second factor. Treat the approved recipient group and delegated object scope as permission for the host to authenticate as those accounts. Exclude privileged identities and protect the administrators, memberships and ACLs defining that scope.

See [enrollment-agent restrictions](../docs/03-Enrollment-Agent-Restrictions.md), [Key Trust delegation](../docs/04-Key-Credential-Link-Delegation.md) and the [installation recipes](README.md).

## Constrained delegation authority

Broker-account delegation limits target services, not recipient users. Local `craft-users` access and NSS identity control limit ordinary callers; a compromised broker can attempt impersonation of other users wherever AD permits it. Protect privileged accounts with domain delegation restrictions and prove denial. Services sharing an AD account/key are not isolated by their SPN labels; use separate target identities where that separation matters. See [broker delegation](../docs/05-Constrained-Delegation.md).

Constrained Delegation uses an AES keytab and Kerberos S4U rather than certificates. Broker credentials stay in private memory. Service tickets may be forwardable/forwarded; the output still carries no TGT or evidence. `craft-maintain` reacquires the whole service batch before the earliest expiry, with no cache-only TGT renewal. KDC policy may shorten service lifetimes. Disable acquisition and stop maintainers before changing policy; existing tickets retain their domain-enforced validity.

## Key Trust certificate handling

The linked directory public key authorizes Key Trust authentication; no enterprise user-certificate CA chain is required. CRAFT creates a temporary self-signed local issuer to sign the PKINIT client certificate. The issuer's private key is released after signing, and neither certificate is installed in OS or AD trust stores.

MIT Kerberos uses the same anchor set to construct the client chain and validate the KDC. For each Key Trust request, CRAFT appends the temporary issuer to an in-memory copy of `kdc-trust.pem` and supplies it as `X509_anchors`. The configured file is unchanged, but that issuer is also a KDC-validation anchor for the request. KDC identity, EKU and CRL checks remain governed by `krb5.conf`. Review this additional per-request anchor against deployment PKI policy.

CRAFT removes its exact directory value before releasing credentials and preserves existing keys. Independent cleanup attempts removal after failed acquisition or worker termination, including uncertain LDAP add outcomes. Cleanup failure blocks cache publication and logs a CRITICAL event when cleanup can run. Host failure or directory unavailability can leave a usable key; inspect affected objects and remove residual credentials.

## Lifetime and encryption policy

Certificate modes default to a ten-hour initial TGT and seven-day renewal window. The KDC controls the grant, and certificate/key lifetime can constrain initial PKINIT validity. Strict mode rejects shortened grants; `require_full_tgt_lifetime=no` permits shorter grants with a warning. Every mode rejects excessive lifetimes, unexpected principals/flags, and non-AES session or ticket encryption.

Enrollment defaults cap certificate validity at ten hours total, including backdating. Supplied certificates may have ordinary validity periods; their expiry still affects fresh authentication. Renewal uses the cached TGT/session key independently of the certificate. Neither certificate expiry, private-key deletion, directory-key removal nor cache deletion revokes already-issued tickets.

## Privilege separation and file custody

Only `craft` is setuid in broker modes. The launcher reads mode policy through a caller-identity worker, then starts each enabled attempt as the caller for `home` or the dedicated `craft` account for a broker mode. The parent receives credential bytes only after permanently dropping to the caller. Certificate, LDAP, CES and Kerberos processing stay outside root. The worker and maintainer must remain ordinary executables.

Only the service account belongs to the `craft` group. Private service files are `root:craft` mode 0640; approved callers join the separate `craft-users` launcher group. Public configuration/trust/CRL files are `root:root` mode 0644. Trusted files and parents must be root-owned, not group/world-writable and not symlinks. Protect Kerberos includes, plugins, dynamic libraries, NSS and OpenSSL configuration/providers as part of the host boundary.

BYOC uses ordinary executables and public configuration without the service account, keytab or private runtime directory. Its PEM pair must be caller-owned and safe as described in [BYOC setup](README.md#byoc-setup). CRAFT leaves supplied files in place; the user must replace and protect them.

The fixed caller-owned mode-0600 `.krb5cc_craft` contains reusable tickets and session keys. Acquisition/validation failure preserves it; successful acquisition replaces it atomically. Exclude credentials from backups, sync and indexing where practicable. Generated keys/certificates stay in memory and temporary memory files, while CA records persist. Memory may reach swap or privileged capture; temporary processing does not guarantee secure erasure.

The optional [GSS-Proxy application setup](../docs/06-GSS-Proxy-and-SELinux.md) authorizes a separate consumer UID to use the issuer's cache through a dedicated socket. The consumer selects an empty in-memory cache for opaque proxy credentials. Unix identity separation and, where configured, SELinux deny direct source access; environment variables alone provide no isolation. The proxy remains able to read user tickets, applications receive usable service contexts, and retained proxy credentials or sessions can outlive a source-cache replacement. Keep the source cache out of the application's `KRB5CCNAME`.

Root or service-account compromise can expose service credentials and their entire authorized scope. Use separate service identities/keys for different scopes, protect export copies and rotate compromised credentials.

## Transport trust and logging

Certificate modes need the MIT PKINIT plugin, approved KDC anchors, current chain CRLs and administrator-configured KDC identity/EKU checks. Enrollment Agent and BYOC also require user-certificate CA trust/CRLs; Enrollment Agent validates the enrollment agent. CRAFT does not download trust material. Keep accepted CAs narrow; the client does not independently pin the actual issuing CA beyond its configured trust set.

Directory connections require LDAP/GSSAPI integrity and encryption with minimum SASL SSF 128. CES requires verified HTTPS with TLS 1.2 or later, no redirects/proxy environment, and the chosen Negotiate or mTLS transport identity. Optional `https-crls.pem` enforces CES server-chain revocation; without it, only HTTPS chain/hostname validation is performed. No OCSP check is implemented.

CRAFT records requests, issuance, Key Trust changes, cache publication, renewal and maintenance through the host AUTHPRIV logging socket. Logging failure blocks startup, credential release and renewal publication; the final launcher publication record follows cache replacement, so failure there can be reported after the cache changed. Local submission does not prove durable retention or forwarding. Configure host logging and the [audit rules](config/craft.audit.rules) for file access, launcher use and network connections. Server/library detail stays in the log; caller and status output use a bounded summary.

## Not claimed

This reference implementation is not independently audited or validated for every AD CS, Key Trust, KDC or scheduler deployment. Recorded tests cover only the scope described in [deployment validation](TESTING.md), including [parser fuzzing](TESTING.md#fuzz-testing). Complete live mapping, revocation, authorization-denial, cleanup and installed privilege checks for the deployed mode.

The optional SELinux cache-label module grants proxy access to a dedicated issuer home; it does not define confinement for CRAFT or arbitrary applications. No dedicated AppArmor or seccomp policy, hardware-key backend, remote approval service, enrollment cancellation, automatic certificate revocation, global acquisition quota or automatic expired-cache collection is provided. Sensitive memory is not locked against swapping. Administrators remain responsible for OS hardening and credential lifecycle. Do not resolve rejection by weakening TLS, CRLs, strong mapping or authorization.

## Immediate disable

Set `enabled=no` in `/etc/craft/config` or remove launcher execute access to stop fresh acquisition through all modes. Removing only setuid stops broker acquisition; a valid home pair remains usable if `home` is enabled. Remove a mode from `modes` to prevent fresh acquisition through that path. Revoke CA agent/recipient authorization or AD delegation separately when the host's authority must be withdrawn.

Acquisition disable does not stop renewal from an existing cache. Inspect each job's status and send SIGTERM to its recorded `maintainer_pid` to stop active maintenance. The cache remains. Already-issued tickets and active service sessions require the domain's incident-response measures.

For Enrollment Agent compromise, withdraw the agent's effective authorization on all relevant CAs, revoke compromised agent/user certificates, publish current revocation data and rotate agent/keytab/mTLS credentials. For Key Trust, revoke the delegation with `Grant-CRAFTKeyCredentialLink.ps1 -Remove`, rotate the keytab and remove only confirmed residual CRAFT values from affected objects. For BYOC, replace/revoke compromised supplied certificates and keys. For Constrained Delegation, remove the broker delegation/protocol-transition permission and rotate the broker keytab. Preserve AUTHPRIV, directory, CA/CES and KDC evidence, repair the cause and repeat acceptance checks before restoring service.
