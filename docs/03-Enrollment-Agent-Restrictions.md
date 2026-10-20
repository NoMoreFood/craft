# CRAFT enrollment agent restrictions

For **Enrollment Agent**, restrict the actual enrollment-agent identity to a dedicated user template and a small approved recipient group on every CA that can accept it. An agent private key permits enrollment for other users; its Certificate Request Agent EKU does not encode a recipient allowlist. Strong KDC mapping can authenticate a correctly issued privileged certificate, so prohibited issuance must be refused by the CA.

Key Trust uses [Key Trust delegation](04-Key-Credential-Link-Delegation.md). BYOC uses an existing certificate and KDC mapping without the agent. The administrator's `modes` list selects and orders the enabled workflows; these recipient rules do not authorize or revoke credentials obtained through another path. Use `modes=enrollment` to test this authorization independently. See [mode selection and setup](../source/README.md#configure-mode-selection).

## Identify the authorization roles

| Identity | Credential or request field | Administrator control |
| --- | --- | --- |
| Enrollment agent | `agent.pem`/`agent.key` signs the EOBO request | Agent-template issuance rights and CA restrictions for that signing identity |
| Submission/directory account | `service_principal`/`submitter.keytab`; mTLS can add a separate transport identity | Directory reads, CES transport, template enrollment and constrained delegation |
| Recipient | Signed `NETBIOS\caller` request and AD-built UPN/SID | Approved recipient group, protected identity attributes and KDC mapping |

The [CA helper](../scripts/Configure-CRAFT-CA.ps1) uses the same named AD account for signing and keytab roles. Provision them separately if the deployment requires it. Transport authentication does not redefine which recipients the signer may represent.

## Configure an explicit CA authorization rule

Example policy:

| Agent | Permitted template | Permitted recipients |
| --- | --- | --- |
| `DOMAIN\svc-linux-enroll` | `CRAFTUser` only | `DOMAIN\CRAFT Approved Users` only |

On each relevant issuing CA:

1. Open **Certification Authority** (`certsrv.msc`), the CA's **Properties**, then **Enrollment Agents**.
2. Select **Restrict enrollment agents**.
3. Remove broad grants applicable to the CRAFT signer, including grants through Everyone or Authenticated Users.
4. Add the actual AD signing identity, select only the dedicated template and authorize only the approved recipient group.
5. Review overlapping rules; a narrow rule does not cancel a broader applicable grant.
6. Apply and test both permitted and prohibited requests.

Restrictions are CA-local. Review alternate/recovery CAs and every exposed enrollment interface. Match rules to the signing principal rather than a certificate friendly name, CN or exporting administrator. Separate agent accounts and keys are needed for separate recipient scopes; issuing two certificates to one account does not create two authorization policies. [Microsoft CA authorization rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/6becda04-e17f-46df-825a-cec64ed0a203).

## Govern the recipient group

Membership authorizes the CRAFT host to authenticate as that account. Admit only required ordinary user/workload accounts, prefer direct membership and avoid nesting broad access groups.

Exclude domain/enterprise administrators, DCs, PKI administrators, `krbtgt`, replication-capable accounts, identities controlling privileged groups/passwords or identity infrastructure, and accounts with critical application/infrastructure administration. Keep the agent/transport identities out of privileged roles and the recipient set.

Review effective access, including nested membership, delegated rights, SID history, ownership and ACLs. `adminCount=1` is a review signal, not a complete privilege classification. A starting inventory is:

```powershell
Import-Module ActiveDirectory
$recipientGroup = Get-ADGroup -Identity 'CRAFT Approved Users'
Get-ADGroupMember -Identity $recipientGroup |
    Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
Get-ADGroupMember -Identity $recipientGroup -Recursive |
    Where-Object ObjectClass -eq 'user' |
    ForEach-Object {
        Get-ADUser -Identity $_.DistinguishedName -Properties Enabled, adminCount, sIDHistory
    } |
    Select-Object SamAccountName, Enabled, adminCount, sIDHistory
```

Review primary-group/cross-domain relationships and unexpected non-user members separately. Protect the group's owner and ACL so recipients, service identities and unauthorized administrators cannot admit targets. Assign a membership owner and approval process, alert on membership/ACL changes, and remove an account before granting it privileged access. Prefer a separate administrative identity that never participates in CRAFT. Any supplemental Deny rules require testing with overlapping/nested memberships; retain the positive allowlist.

## Control both certificate templates

| Template | Required controls |
| --- | --- |
| Enrollment agent | Enroll only designated agents/provisioning administrators; Certificate Request Agent EKU; protected owner/write/ACL rights; review alternate templates issuing agent credentials |
| CRAFT user | One authorized Certificate Request Agent signature; AD-built subject/UPN and retained SID extension; explicit CA:FALSE and logon usage; narrow enrollment rights; protected template administration and CA-enforced short validity |

The [required user-certificate profile](../source/README.md#enrollment-agent-and-dedicated-template) specifies key size, all three EKUs, template OID and validity caps. The agent signature proves a qualifying signer approved the request; the CA recipient restriction decides whom it may represent. Template Enroll permission alone is not a recipient allowlist. [Microsoft signature enforcement](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/35e6361f-8d69-4fbe-a586-5f1c8395ffcd).

For infrequent agent provisioning, consider manager approval and limiting publication of its issuance template. Unpublishing a template does not revoke issued agent certificates. The automatic user flow requires immediate issuance and one signature; pending approval or multiple signers need a separate workflow. Review reenrollment flags and alternate renewal interfaces so previously issued credentials do not bypass the intended approval boundary.

## Preserve identity and transport controls

Keep **Supply in the request** and CA-wide `EDITF_ATTRIBUTESUBJECTALTNAME2` disabled for this design. Build the recipient UPN/SID from AD and retain strong KDC mapping. Protect identity attributes and `altSecurityIdentities` administration. Review issuance-policy/group mappings such as `msDS-OIDToGroupLink` that could give an ordinary certificate holder extra authorization. Keep CA/CES/DC security updates current. [Microsoft mapping guidance](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16), [PKI controls](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786426(v=ws.11)).

Expose only required enrollment endpoints. Configure verified CES HTTPS, narrow CES-to-CA constrained delegation, and protections against NTLM relay, including Extended Protection where applicable. Keep Kerberos-only Negotiate or the reviewed mTLS mapping functional after hardening. A valid transport, signature and request must still be refused for a prohibited recipient. [Microsoft AD CS relay guidance](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429).

Short certificate validity, correct mapping, Linux launcher checks and MFA-protected interactive sign-in do not define the CA recipient boundary. Protected Users can impose ticket restrictions incompatible with CRAFT's requested renewal; a local strict-lifetime failure does not prove the issued certificate is unusable by another client.

## Protect credentials and policy administrators

Keep operational agent keys and service credentials `root:craft` mode 0640, with only the dedicated service account in `craft`. Approved callers join `craft-users`, without access to service credentials. Assume root or service-account compromise exposes the software agent key; an attacker using another client can bypass local caller checks.

Use distinct credentials for distinct authorization scopes, protected deployment channels and backups, planned rotation, and prompt removal of export copies. CRAFT has no hardware-key or external signing backend. A PFX password protects an export but does not add a second factor to an unattended operational key.

Agent/transport accounts must not administer the CA, templates, recipient group or PKI servers. Protect CA signing keys and management systems: compromise of those controls can defeat recipient restrictions. See [CRAFT security and operations](../source/SECURITY.md).

## What the provisioning helper verifies

[`Configure-CRAFT-CA.ps1`](../scripts/Configure-CRAFT-CA.ps1) verifies narrow agent/template permissions and explicit CA agent/template/recipient restrictions before publication/export. Configure them first. Its target checks do not establish every recipient's effective privilege or secure all alternate CAs/interfaces.

The helper does not install CES or complete SPNs/delegation, full trust/CRL bundles or Linux installation. Review its preview and the [provisioning instructions](../source/README.md#windows-provisioning-helper), including account password resets and credential export.

## Prove denial at the CA

Use isolated lab identities and otherwise valid requests. A malformed request, unreachable endpoint or wrong keytab does not prove recipient authorization.

| Request | Required result |
| --- | --- |
| Approved ordinary recipient, intended signer/template | Issuance succeeds and PKINIT returns that account's TGT |
| Recipient outside the approved group, including an excluded privileged test identity | CA refuses issuance |
| Approved recipient with unauthorized template or signer | CA refuses issuance |
| Missing qualifying agent signature | CA refuses issuance |
| Another account's identity supplied in the CSR | CA builds the authorized requester's AD identity or refuses; no other-account authentication certificate |
| Recipient removed from group or agent authorization withdrawn | Fresh prohibited issuance stops after policy/replication propagation |
| Alternate CA/interface or reenrollment | No route bypasses the intended recipient/template/approval policy |

Also verify the configuration review detects overlapping broad grants and inappropriate recipient membership. The native rule does not automatically subtract privileged accounts from an allowed group.

Record CA request ID/disposition, policy error, signer, template, recipient and effective rule. Inspect successful UPN/SID/usages/validity and KDC principal. Do not obtain production privileged credentials to demonstrate a negative case. Complete the wider [enrollment acceptance checklist](../source/TESTING.md#live-acceptance-checklist).

## Audit and respond to compromise

Enable **Audit Certification Services** and the corresponding CA audit categories. Centralize issuance/denial/revocation, policy/template changes and recipient-group changes. Correlate CRAFT AUTHPRIV records, CA requests and DC event 4768; determine which deployed fields identify the signer, transport account and recipient. Keep credential bytes/passwords out of logs.

CA events include 4886/4887/4888 for received/issued/denied requests, 4870 for revocation and 4882/4885/4891 for security/audit/configuration changes. Alert on unexpected recipients, templates/signers, issuance volume, new agent credentials and policy/membership changes. [Microsoft CA audit events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services), [TGT audit fields](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768).

On suspected compromise:

1. Disable fresh acquisition, stop active maintainers and isolate the affected host.
2. Withdraw the agent's effective authorization on every relevant CA, revoke its certificate, publish revocation data and verify new prohibited requests fail.
3. Rotate affected agent/keytab/mTLS credentials and repair the compromise before restoring authority.
4. Identify and revoke affected issued user certificates, including unexpected templates/recipients; distribute current revocation data.
5. Investigate already-issued tickets, service sessions and downstream access using the incident-response process.
6. Restore reviewed policy and repeat permitted/denied acceptance checks.

Agent revocation does not revoke certificates it previously authorized. Certificate expiry/revocation and cache deletion do not guarantee immediate ticket/session termination.

## Deployment acceptance criteria

Enable Enrollment Agent only with an explicit, tested signer/template/recipient boundary on every relevant CA, a reviewed nonprivileged recipient set, protected policy administrators and successful permitted/denied requests. Keep privileged accounts in a separate reviewed workflow. Record ownership for credential rotation, CRL refresh, recipient review and incident response.
