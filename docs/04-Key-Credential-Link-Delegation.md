# CRAFT credential linking and Key Trust delegation

Credential linking is CRAFT's mode 2 privileged acquisition path, using AD Key Trust. When no home certificate pair is present and `mechanism=key_trust` is configured, the dedicated service account writes a temporary public key to the caller's `msDS-KeyCredentialLink`, performs PKINIT against it, and then removes the key. It needs no user-certificate CA enrollment, CES endpoint, enrollment agent or user template: the directory write itself establishes trust, and the domain controller authenticates the key through the Key Trust (NGC) model that Windows Hello for Business uses.

The decisive safeguard is the delegated write scope. The ability to write `msDS-KeyCredentialLink` on an account is equivalent to the ability to authenticate as that account; this is the basis of the "Shadow Credentials" technique. CRAFT uses it deliberately and with narrow, administrator-granted delegation, removes the key immediately after authentication, and never grants the service account broad directory write. Treat the delegated object scope as an authorization boundary with the same care as the enrollment-agent recipient group.

Follow [mode 2 setup](../source/README.md#mode-2-setup-privileged-credential-linking) for Linux installation and configuration.

This page explains the mechanism, the authorization boundary, the delegation helper, the residual risks and the live tests. The configuration examples are recommendations, not a claim that these controls are already deployed in your domain. For the enrollment-agent (certificate-trust) fallback, see [Enrollment Agent Restrictions](03-Enrollment-Agent-Restrictions.md); for the entirely unprivileged path, see the [home certificate workflow](../source/README.md#mode-3-workflow-unprivileged-windows-exported-certificate).

## How CRAFT uses Key Trust

1. A caller runs `craft` with no home pair. The setuid launcher runs the worker as the dedicated service account, exactly as for enrollment.
2. The worker reads `mechanism=key_trust`, acquires a Kerberos credential for the service account from `submitter.keytab`, and binds to the writable domain controller `kt_dc_url` over LDAP with SASL/GSSAPI integrity and confidentiality.
3. It resolves the caller's unique directory object (`sAMAccountName=<Linux username>`) to its distinguished name and `userPrincipalName`.
4. It generates a fresh RSA-2048 key and a short-lived locally issued certificate carrying the resolved UPN.
5. It builds a version-2 Key Credential (MS-ADTS 2.2.20) advertising that key as an NGC/Key Trust credential and **adds** exactly that one value to `msDS-KeyCredentialLink`, leaving any existing Windows Hello keys untouched.
6. It performs PKINIT for `<Linux username>@<realm>`. The KDC matches the certificate's public key against the Key Credential and issues a TGT. CRAFT validates the returned principal, flags, AES encryption and lifetimes.
7. An independent cleanup process **removes** the temporary value before any credential bytes leave the worker. It also attempts cleanup after acquisition failure or worker termination and uncertain LDAP add outcomes, retrying with a fresh connection. If cleanup still fails, CRAFT refuses cache publication and logs a CRITICAL AUTHPRIV event naming the residual credential for administrator removal. Host failure or directory unavailability can leave a usable key behind.

![Mode 2 credential linking, Key Trust PKINIT and mandatory cleanup before cache publication.](diagrams/03-credential-linking-sequence.svg)

## The authorization boundary

Three facts define the boundary:

- **The write is the authentication.** A DC in Key Trust mode will issue a TGT for any account whose `msDS-KeyCredentialLink` contains a key the requester can prove possession of. There is no second factor, CA policy or enrollment-agent signature in this path. Whoever can write the attribute on an account can authenticate as it.
- **CRAFT's checks are client-side.** The worker verifies the caller's Linux UID/name, resolves one directory object, requests the fixed caller principal and validates the returned ticket. An attacker who obtains the service account's keytab and the delegated write can bypass these checks with a different client. Therefore the directory must enforce the write scope independently.
- **The delegation is the control.** Active Directory decides which objects the service account may modify. Grant the write over an Organizational Unit of ordinary, non-privileged users (or a single user), and nothing else.

Keep three identities distinct:

| Identity | Role in CRAFT | Relevant control |
| --- | --- | --- |
| Service account | `service_principal` / `submitter.keytab`; binds to the DC and writes `msDS-KeyCredentialLink` | The delegated object scope, keytab custody, and exclusion from privileged roles |
| Target | The calling user's AD account whose attribute is written and who is authenticated | The delegated OU/user membership and KDC Key Trust mapping |
| Domain controller | Serves both the LDAP write and the Key Trust PKINIT | `kt_dc_url` must name the same writable DC as the KDC in `krb5.conf` |

## Delegate the minimum permission

Use [`Grant-CRAFTKeyCredentialLink.ps1`](../scripts/Grant-CRAFTKeyCredentialLink.ps1) to grant the service account **ReadProperty and WriteProperty on the single `msDS-KeyCredentialLink` attribute**, scoped to one OU (inherited to descendant user objects) or one user. It grants no other right: not GenericWrite, not GenericAll, not write over other attributes, and not control of the object.

```powershell
# Preview first.
.\scripts\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll `
    -TargetOU "OU=CRAFT Users,OU=Service Accounts,DC=domain,DC=local" -WhatIf

# Grant over a dedicated OU of ordinary users.
.\scripts\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll `
    -TargetOU "OU=CRAFT Users,OU=Service Accounts,DC=domain,DC=local"

# Or over a single user.
.\scripts\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll -TargetUser alice

# Revoke.
.\scripts\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll `
    -TargetOU "OU=CRAFT Users,OU=Service Accounts,DC=domain,DC=local" -Remove
```

The helper refuses a privileged target, the domain root and the default containers (`CN=Users`, `CN=Computers`, `CN=Managed Service Accounts`) unless `-Force` is supplied. It flags a target user with `adminCount=1` or privileged group membership, and flags an OU that contains such users. It is idempotent and supports `-WhatIf`. It changes AD permissions; review the service account, the scope and the printed rule before applying.

Why a dedicated OU is the right scope:

- Put only the ordinary user or workload accounts that require this deployment into the delegated OU. Prefer a purpose-built OU over an existing one so the boundary is explicit and auditable.
- Keep administrative identities, Domain Admins, Enterprise Admins, domain controllers, PKI administrators, `krbtgt`, accounts with directory-replication rights, and accounts that control privileged groups or identity infrastructure out of the OU.
- Review effective privilege, not just group names: nested membership, delegated AD permissions, SID history, ownership and ACLs, and access to critical systems. `adminCount=1` is a useful signal, not a complete classification.
- If an account in the delegated OU later becomes privileged, move it out before granting that privilege and account for any credentials already obtained. Prefer a separate administrative account that never participates in CRAFT.

Protect the delegated object and OU: restrict who can write their ACL (`WriteDacl`/`WriteOwner`) or move accounts into the OU, since either can widen the boundary. Audit and alert on delegation changes. The service account must not have rights that let it rewrite its own delegation.

## Keep the service account and keytab contained

The service account can authenticate as every account in its delegated scope. Treat its keytab as a high-value credential:

- Keep `submitter.keytab` `root:craft` mode 0640 and readable only by the dedicated account, as for enrollment. Assume root or service-account compromise exposes it.
- Give the service account no privileged roles, no CA or DC administration, and no ability to change its own delegation or the delegated OU's membership or ACL.
- Use distinct service accounts and distinct delegations for workloads that require different target scopes. A shared account widens the blast radius of compromise to the union of its scopes.
- Rotate the keytab on suspected compromise, and verify afterward that the account can still write only the intended scope.

## Interoperability requirements

- **Key Trust support.** The domain must support NGC/Key Trust key-based authentication (a schema exposing `msDS-KeyCredentialLink` and a writable Windows Server 2016-or-later KDC with a current PKINIT certificate). Key Trust PKINIT is the same model Windows Hello for Business "key trust" deployments use.
- **Same DC for write and KDC.** Set `kt_dc_url` to the writable DC that `krb5.conf` names as the KDC, so the written key is visible to the KDC without replication delay. A different DC can reject the PKINIT until the attribute replicates.
- **KDC certificate and trust.** As in every CRAFT path, the KDC must present a PKINIT/KDC certificate that chains to `kdc-trust.pem` with current CRLs, and the Linux client validates it. Key Trust changes how the KDC authenticates the client, not how the client validates the KDC.
- **PKINIT freshness.** CRAFT delegates PKINIT negotiation to MIT Kerberos. Its plugin supports freshness tokens; verify it against the actual KDC policy rather than treating freshness enforcement as an automatic blocker. See [MIT PKINIT freshness support](https://web.mit.edu/kerberos/krb5-latest/doc/admin/pkinit.html#freshness-tokens).
- **Strong mapping.** Key Trust is itself a strong, key-based mapping and is unaffected by KB5014754 certificate-mapping enforcement for CA-issued certificates. The local certificate identity is authorized by the directory key, not an NTAuth user-certificate chain. KDC certificate trust is still required. See [Microsoft key-trust requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/).

## Compared with the enrollment-agent fallback

| Property | Key Trust (`key_trust`) | Enrollment agent (`enrollment`) |
| --- | --- | --- |
| Requires user-certificate enrollment / CES / template | No | Yes |
| Requires an enrollment-agent certificate | No | Yes |
| Privileged directory operation | Write `msDS-KeyCredentialLink` on the target | Sign an EOBO request as the agent |
| Authorization boundary | Delegated object/OU write scope | CA enrollment-agent recipient restrictions |
| Directory / CA residue | Temporary directory key removed on success; failed cleanup needs intervention | CA retains issued certificate and audit record |
| Client certificate identity | Locally issued, authorized by the linked public key | CA-issued, chain-verified |

Key Trust removes user-certificate CA enrollment and the long-lived enrollment-agent key from acquisition while retaining KDC certificate trust, at the cost of granting a directory write whose scope you must govern. Choose one fallback per deployment. Both privileged modes remain subordinate to mode 3's supplied-certificate acquisition path, which uses no service account at all.

## Prove the boundary

Use an isolated lab and disposable identities. Make prohibited attempts otherwise valid (correct keytab, reachable DC, well-formed key) so that a failure reflects the delegation, not a malformed request.

| Test case | Required observation |
| --- | --- |
| Approved ordinary user within the delegated OU | CRAFT adds the key, PKINIT authenticates the intended account, and the key is removed afterward |
| User outside the delegated scope | The directory rejects the `msDS-KeyCredentialLink` write; no TGT is issued |
| Privileged account (admin, DC, `krbtgt`) excluded from the delegated scope | The write is refused; the helper rejects privileged targets. An OU grant does not become a privilege filter if an account is later made privileged. |
| Service account attempting another attribute or object | The directory rejects it; the delegation grants only the one attribute on the scoped objects |
| Interrupted or failed PKINIT | Cleanup attempts run; inspect the object and AUTHPRIV log, and remove any residual key |
| `kt_dc_url` pointing at a non-KDC replica | Diagnose replication-induced PKINIT failures; correct it to the KDC |
| Revoked delegation (`-Remove`) | Fresh acquisition fails after the ACL change propagates; evaluate issued tickets separately |
| Keytab withdrawn or rotated | The LDAP bind fails and no key is written |

Record the object DN, the service account, the DC, and the resulting KDC principal for control requests. Confirm no residual `msDS-KeyCredentialLink` value remains after each run; `Get-ADUser <user> -Properties msDS-KeyCredentialLink` should show only legitimate Windows Hello keys.

## Audit and respond to compromise

- Audit directory-service changes (event 5136) for `msDS-KeyCredentialLink` modifications, and correlate add/remove pairs with CRAFT's AUTHPRIV `certificate_source=key_trust` events and DC event 4768 (certificate-based TGT requests).
- Alert on `msDS-KeyCredentialLink` writes by the service account outside the delegated OU, writes to privileged accounts, keys that are added but not promptly removed, and any change to the delegation or the delegated OU's membership or ACL.
- On suspected compromise: stop CRAFT on the host, revoke the delegation (`-Remove`), rotate the keytab, enumerate and clear any residual `msDS-KeyCredentialLink` values on affected accounts, and follow your incident-response process for already-issued tickets. Clearing a Key Credential or rotating the keytab does not revoke a TGT already issued.

## Deployment acceptance criteria

Accept the Key Trust fallback only when the service account's `msDS-KeyCredentialLink` write is delegated to a specific, reviewed, non-privileged object scope; the keytab and the delegation administrators are protected separately from the CRAFT host; `kt_dc_url` names the KDC's writable DC; and the lab shows directory refusal for out-of-scope and privileged targets with clean removal of the temporary key. For accounts that administer the domain or its identity infrastructure, use a separate, explicitly reviewed workflow and keep them outside every CRAFT delegation.
