# CRAFT Key Trust delegation

For **mode 2 privileged credential linking**, delegate only ReadProperty/WriteProperty on `msDS-KeyCredentialLink` over a reviewed set of ordinary users. This write permits authentication as those accounts, so its scope is the authorization boundary. It requires no user-certificate CA enrollment, CES, agent or user template; KDC certificate trust and current CRLs remain required.

Complete [mode 2 setup](../source/README.md#mode-2-setup-privileged-credential-linking). CRAFT first checks the caller's home pair; test delegation with both PEM files absent. A valid pair uses [mode 3](../source/README.md#mode-3-setup-unprivileged-windows-exported-certificate) without the directory write, while partial/invalid inputs fail without privileged acquisition.

## Prepare the service identity and DC

Provision a nonprivileged AD service account with an AES keytab matching `service_principal`. Install `submitter.keytab` as `root:craft` mode 0640, with only the dedicated service account in the Linux `craft` group. Approved callers join `craft-users`. Keep the service identity unable to change its delegation, target ACLs or OU membership.

Use a schema exposing `msDS-KeyCredentialLink` and a writable DC supporting NGC/Key Trust PKINIT, as provided by Windows Server 2016 or later. A functional-level label alone is insufficient. Configure **the same DC** as `kt_dc_url` and the KDC in `krb5.conf` so PKINIT can see the written key immediately. Use `ldap://`; LDAP/GSSAPI requires integrity and encryption with minimum SASL SSF 128.

Provision the KDC certificate, approved anchors and current chain CRLs. Remove an unnecessary `pkinit_pool` reference to user-certificate trust or replace it with KDC intermediates as described in [shared installation](../source/README.md#shared-linux-installation). Review [Key Trust's temporary issuer trust scope](../source/SECURITY.md#key-trust-certificate-handling) and verify MIT PKINIT freshness interoperability against the deployed DC policy. [Microsoft Key Trust requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/), [MIT freshness tokens](https://web.mit.edu/kerberos/krb5-latest/doc/admin/pkinit.html#freshness-tokens).

## Delegate the minimum permission

Run [`Grant-CRAFTKeyCredentialLink.ps1`](../scripts/Grant-CRAFTKeyCredentialLink.ps1) from the repository root on a Windows administration host with the ActiveDirectory module and permission to change the selected object's ACL. Choose one OU or one user:

```powershell
# Preview an OU grant.
.\scripts\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll `
    -TargetOU 'OU=CRAFT Users,DC=domain,DC=local' -WhatIf

# Apply the reviewed OU grant.
.\scripts\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll `
    -TargetOU 'OU=CRAFT Users,DC=domain,DC=local'

# Or delegate over one user.
.\scripts\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll -TargetUser alice

# Revoke the helper's matching OU rule.
.\scripts\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll `
    -TargetOU 'OU=CRAFT Users,DC=domain,DC=local' -Remove
```

The OU rule inherits only to descendant user objects; a user rule applies only to that object. The helper grants no GenericWrite/GenericAll or other attribute rights, is idempotent and supports `-WhatIf`. `-Remove` removes its matching explicit rule; separately review other permissions that might still authorize the service account.

The helper refuses privileged targets, the domain root and default containers (`CN=Users`, `CN=Computers`, `CN=Managed Service Accounts`) unless `-Force` is supplied. It checks privileged group membership and `adminCount=1`, including users in an OU. These checks are guardrails, not a continuing privilege filter. Confirm effective rights after applying the rule; other grants, Deny rules or blocked inheritance can change the outcome.

## Govern the delegated scope

Use a dedicated OU containing only ordinary accounts required by the deployment. Exclude administrative identities, DCs, `krbtgt`, PKI/identity administrators, replication-capable accounts and accounts controlling privileged groups or critical infrastructure.

Review nested membership, delegated AD rights, SID history, ownership/ACLs and effective application access. `adminCount=1` is a signal, not a complete classification. Remove an account from scope before granting privileged access; prefer a separate administrative identity that never participates in CRAFT.

Protect who can move accounts into the OU or change its ACL/owner, since either can widen the authority. Alert on membership, object movement and delegation changes. Use separate service identities/delegations for workloads with different target scopes. Treat the keytab as permission to authenticate as every scoped target and rotate it on suspected compromise.

## Verify acquisition and cleanup

CRAFT resolves one caller account on the selected DC, generates a fresh RSA key (default 3072 bits; `key_bits` accepts 2048/3072/4096), adds one temporary public-key credential and performs PKINIT for `<Linux username>@<realm>`. It validates the TGT and removes its exact value before cache publication, preserving legitimate Windows Hello keys.

An independent process attempts removal after successful or failed acquisition, worker termination and uncertain LDAP add outcomes. It retries with a fresh connection. Cleanup failure blocks publication; CRITICAL AUTHPRIV records identify the object and worker when cleanup can report. Continuing directory failure or host loss can leave a standing credential.

Capture the attribute on the same DC before and after a run:

```powershell
Get-ADUser alice -Server dc01.domain.local -Properties msDS-KeyCredentialLink |
    Select-Object SamAccountName, DistinguishedName, msDS-KeyCredentialLink
```

Compare actual values with the prior inventory. Logs identify the object by GUID and the worker PID, rather than logging public-key/credential bytes. CRAFT-generated values carry DeviceID `c7a4f7b2-5d1e-4c9a-9b3f-43524146544b`; correlate that marker, operation time and audit evidence before selecting a residual value for removal. Do not clear the entire attribute or remove legitimate keys. If needed, remove a confirmed exact value with authorized AD tools on that same DC.

## Prove the boundary

Use disposable identities and otherwise valid requests so a failure demonstrates delegation rather than malformed input or connectivity.

| Test | Required observation |
| --- | --- |
| Approved ordinary target | Authentication returns the intended TGT; only CRAFT's value is added/removed |
| Out-of-scope or excluded privileged target | Directory refuses the write; no TGT is obtained through this path |
| Other attribute/object | Service account cannot modify it through this delegation |
| Failed/interrupted PKINIT or uncertain add | Cleanup is attempted; inspect attribute and logs for residual values |
| Forced cleanup outage | Cache publication fails; residual key is identified and removed by an administrator |
| Revoked helper rule | Fresh acquisition fails once ACL changes propagate, unless another reviewed grant still authorizes it |
| Withdrawn/rotated keytab | Old credential cannot bind or write |
| Different LDAP/KDC replicas | Detect replication-related failure and restore same-DC configuration |

Record the target DN/GUID, service identity, DC, prior/final attribute values and resulting KDC principal. Complete the [common and Key Trust acceptance checks](../source/TESTING.md#key-trust-acceptance-checks).

## Audit and respond to compromise

Enable directory-service change auditing and the appropriate object/attribute SACL for event 5136. Correlate `msDS-KeyCredentialLink` add/remove pairs with CRAFT AUTHPRIV records (`certificate_source=key_trust`) and DC TGT event 4768. Alert on writes outside scope, privileged targets, keys not promptly removed and changes to delegation or OU administration. [Microsoft directory-change auditing](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136).

On suspected compromise, disable fresh acquisition, stop active maintainers, revoke the delegation, rotate the keytab, inspect affected accounts and remove confirmed residual values. Review other grants before restoring authority. Follow incident response for issued tickets and downstream access: clearing a key or rotating the keytab does not revoke an issued TGT. See [operational disable](../source/SECURITY.md#immediate-disable).

## Deployment acceptance criteria

Enable mode 2 only with a specific reviewed nonprivileged scope, protected keytab and delegation administrators, same-DC LDAP/PKINIT, proven write denial outside scope and clean removal after success/failure. Assign owners for residual-key response, directory auditing, permission review and credential rotation.
