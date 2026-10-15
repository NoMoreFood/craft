# Service tickets through broker constrained delegation

Mode 4 uses a dedicated AD broker account to obtain selected service tickets for the calling Linux user. S4U2Self performs protocol transition; S4U2Proxy requests each approved service. The published cache contains only those final tickets and session keys. The broker TGT, S4U2Self evidence and proxy metadata remain private to the worker. There is no user TGT and no certificate enrollment, PKINIT or directory write.

Set `modes=constrained_delegation` to require this workflow exclusively. Adding certificate modes to the ordered list explicitly authorizes a TGT if one of them succeeds. Use only the service mode when a TGT would violate the deployment's policy; otherwise choose the order that fits application needs and the environment's capabilities.

## Authorize the broker

Use a dedicated ordinary service account with an AES keytab and a unique SPN. On an authorized AD administration host, adapt this example for an existing broker account and the actual services:

```powershell
$broker = Get-ADUser 'svc-craft-broker'
$targets = @('cifs/files.domain.local', 'HTTP/portal.domain.local')
Set-ADUser $broker -KerberosEncryptionType AES128,AES256
setspn.exe -S CRAFT/broker.domain.local DOMAIN\svc-craft-broker
Set-ADAccountControl $broker -TrustedForDelegation $false -TrustedToAuthForDelegation $true
Set-ADUser $broker -Replace @{'msDS-AllowedToDelegateTo' = $targets}
Get-ADUser $broker -Properties servicePrincipalName,msDS-AllowedToDelegateTo,TrustedForDelegation,TrustedToAuthForDelegation |
    Format-List SamAccountName,servicePrincipalName,msDS-AllowedToDelegateTo,TrustedForDelegation,TrustedToAuthForDelegation
```

This is account-based constrained delegation with protocol transition: **Trust this user for delegation to specified services only**, **Use any authentication protocol**. `TrustedForDelegation` must remain false. The replacement intentionally sets the dedicated broker's complete target list. Verify each target SPN is registered uniquely to the account running the intended service, and that its current keys support AES. Local CRAFT configuration cannot authorize a target that AD refuses. This workflow requires forwardable S4U2Self evidence and does not configure resource-based delegation.

Export the dedicated broker keytab using your approved account provisioning process. For a newly provisioned, otherwise unused broker, an example is:

```powershell
ktpass.exe /out C:\SecureExport\submitter.keytab /princ CRAFT/broker.domain.local@DOMAIN.LOCAL `
    /mapuser DOMAIN\svc-craft-broker /mapop set /ptype KRB5_NT_PRINCIPAL /crypto AES256-SHA1 /pass *
```

`ktpass` changes account credentials and mappings. Coordinate rotation and replace every deployed copy; do not apply it to a shared service identity. Protect the export directory and transfer the keytab securely. On Linux, install it as `/etc/craft/submitter.keytab`, `root:craft` mode 0640. Use the exact keytab principal as `service_principal`. Follow the [mode 4 installation recipe](../source/README.md#mode-4-setup-service-tickets-through-constrained-delegation) for Linux configuration, caller permissions and enablement.

## Understand the authorization boundary

The Linux real UID and NSS username choose `<username>@<realm>`; callers cannot supply another user or target SPN. Root controls the configured target list. Home certificates are ignored in this mode. Each target uses an explicit same-realm `service/host@REALM`; requests for TGTs, the broker principal, wildcards or other realms are refused.

The broker's AD delegation permission defines which services it can impersonate users to; it is not a recipient-user allowlist. Restrict local access through `craft-users` and protect Linux account assignment. Exclude privileged accounts through domain policy, including Protected Users or **Account is sensitive and cannot be delegated**, and prove the applicable denial in your domain. A compromised broker can attempt impersonation beyond the local caller group wherever AD permits it.

SPN restrictions do not provide isolation between services sharing an AD account and key. Tickets can be usable under alternate service names backed by that same key. Prefer dedicated target service identities when isolation between services matters, and avoid granting delegation to sensitive domain-controller services. Ordinary service authorization still applies to the impersonated user. CRAFT does not perform an MFA challenge.

## Use and maintain the cache

Run `craft` as the intended non-root Linux user. Point applications at the returned `KRB5CCNAME`. They must request the configured SPNs exactly, including case; aliases, canonicalization or additional services may require additional approved entries. Validate the actual application: some Kerberos clients require a TGT before attempting service authentication and cannot use a service-only cache. A cache without a TGT cannot obtain arbitrary new service tickets. One failed target rejects this mode's entire batch; the old cache remains unless another explicitly enabled mode succeeds.

`service_ticket_seconds` requests the maximum lifetime, default ten hours. The KDC may shorten it, and CRAFT accepts a shorter usable AES grant. TGT lifetime/renewal settings do not control this mode. Final service tickets can carry forwardable/forwarded flags from S4U; this does not mean a TGT was exported.

`craft-maintain` refreshes the whole batch through the broker before its earliest service ticket expires. It never performs TGT renewal for a service-only cache. Keep the broker keytab/KDC available and the acquisition interval shorter than the refresh interval permitted by actual ticket grants. Status reports `ticket_kind=service`, the earliest `ticket_expires`, and `renew_until=0`. Applications must reload replaced caches when authenticating again.

When switching from a TGT mode, stop existing maintainers and remove the old CRAFT cache before starting mode 4. Configuration changes do not revoke existing credentials, and an existing TGT maintainer can still renew its cached TGT. On compromise, disable acquisition, stop maintainers, remove the broker's delegation and rotate its keytab. Already-issued tickets and established sessions remain subject to domain incident-response procedures.

## Verify the deployment

Complete the [constrained-delegation acceptance checks](../source/TESTING.md#constrained-delegation-acceptance-checks). Inspect every cache record, authenticate to a real approved service, and prove denial for an unapproved target and a nondelegable user. Repeat after broker or target-key rotation.

The implementation uses the public [MIT GSSAPI S4U interface](https://web.mit.edu/kerberos/krb5-current/doc/appdev/gssapi.html#constrained-delegation-s4u). See Microsoft's [constrained delegation overview](https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview) and [delegation flags and attributes](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/configure-kerberos-delegation-group-managed-service-accounts) for the AD policy model.
