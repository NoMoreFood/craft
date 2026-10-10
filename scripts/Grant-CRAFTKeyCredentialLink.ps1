#Requires -Version 5.1

<#
.SYNOPSIS
    Delegates write access to the msDS-KeyCredentialLink attribute to the CRAFT service
    account on a single Organizational Unit or user, for the Key Trust fallback.

.DESCRIPTION
    CRAFT's key_trust mechanism obtains a Kerberos TGT without a CA. When no home
    certificate pair is present, the dedicated service account writes a temporary
    self-signed key to the caller's msDS-KeyCredentialLink, performs Key Trust PKINIT,
    and then removes that key. This script grants the service account the least-privilege
    permission required for that write: ReadProperty and WriteProperty on the single
    msDS-KeyCredentialLink attribute, scoped to one OU (inherited to descendant user
    objects) or to one user. It grants no other right.

    The ability to write msDS-KeyCredentialLink on an account is equivalent to the ability
    to authenticate as that account (the "Shadow Credentials" technique). Treat the delegated
    scope as an authorization boundary: delegate only over an OU of ordinary, non-privileged
    users, and keep privileged accounts (administrators, domain controllers, service accounts
    with elevated rights, krbtgt) outside it. This script refuses privileged targets and the
    default containers unless -Force is supplied, and -Remove revokes a delegation.

    This changes Active Directory permissions. Review the service account, the target scope
    and the resulting access rule, and run with -WhatIf first. It does not install CRAFT,
    create the service account, or configure the KDC, trust or CRLs.

.PARAMETER ServiceAccount
    The CRAFT directory service account (sAMAccountName, UPN or distinguishedName). Its
    service_principal in /etc/craft/config and submitter.keytab authenticate the LDAP bind.

.PARAMETER TargetOU
    distinguishedName of the Organizational Unit to delegate over. The permission is inherited
    by descendant user objects only.

.PARAMETER TargetUser
    sAMAccountName, UPN or distinguishedName of a single user to delegate over.

.PARAMETER Remove
    Revoke the delegation instead of granting it.

.PARAMETER Force
    Permit a privileged target or a default container. Review the risk before using it.

.EXAMPLE
    .\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll `
        -TargetOU "OU=CRAFT Users,OU=Service Accounts,DC=domain,DC=local" -WhatIf
    Previews delegating the attribute write over an OU of ordinary users.

.EXAMPLE
    .\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll -TargetUser alice
    Delegates over a single user.

.EXAMPLE
    .\Grant-CRAFTKeyCredentialLink.ps1 -ServiceAccount svc-linux-enroll `
        -TargetOU "OU=CRAFT Users,DC=domain,DC=local" -Remove
    Revokes the delegation.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High", DefaultParameterSetName = "OU")]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceAccount,

    [Parameter(Mandatory, ParameterSetName = "OU")]
    [ValidateNotNullOrEmpty()]
    [string]$TargetOU,

    [Parameter(Mandatory, ParameterSetName = "User")]
    [ValidateNotNullOrEmpty()]
    [string]$TargetUser,

    [switch]$Remove,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Well-known schemaIDGUIDs, used only when the live schema lookup is unavailable.
$KeyCredentialLinkGuid = [Guid]"5b47d60f-6090-40b2-9f37-2a4de88f3063"
$UserClassGuid = [Guid]"bf967aba-0de6-11d0-a285-00aa003049e2"

function Write-Step([string]$message)
{
    Write-Host "`n[+] $message" -ForegroundColor Green
}

function Write-Info([string]$message)
{
    Write-Host "    $message" -ForegroundColor Cyan
}

function Write-Warn([string]$message)
{
    Write-Host "    [!] $message" -ForegroundColor Yellow
}

function Resolve-Account([string]$Identity, [bool]$UserOnly = $false)
{
    # Resolve a user, group-managed service account or computer to its SID and name.
    $commands = if ($UserOnly) { @("Get-ADUser") } else { @("Get-ADUser", "Get-ADServiceAccount", "Get-ADComputer") }
    if ($Identity.Contains("@") -and -not $Identity.StartsWith("CN=", [StringComparison]::OrdinalIgnoreCase))
    {
        # UPNs require an escaped attribute search rather than the Identity parameter.
        $escaped = $Identity.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
        $escaped = $escaped.Replace([string][char]0, '\00')
        $accounts = @(foreach ($command in $commands)
        {
            & $command -LDAPFilter "(userPrincipalName=$escaped)" -ErrorAction Stop
        })
        if ($accounts.Count -ne 1) { throw "Account UPN '$Identity' did not resolve to exactly one account." }
        return $accounts[0]
    }
    foreach ($command in $commands)
    {
        try { return & $command -Identity $Identity -ErrorAction Stop }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] { continue }
    }
    throw "Account '$Identity' was not found in the selected account types."
}

function Get-SchemaGuid([string]$SchemaNC, [string]$LdapDisplayName, [Guid]$Fallback)
{
    # Prefer the live schema definition; fall back to the well-known GUID if it cannot be read.
    try
    {
        $object = Get-ADObject -SearchBase $SchemaNC -SearchScope OneLevel `
            -LDAPFilter "(lDAPDisplayName=$LdapDisplayName)" -Properties schemaIDGUID -ErrorAction Stop
        if ($object -and $object.schemaIDGUID) { return [Guid]$object.schemaIDGUID }
    }
    catch { }
    Write-Warn "Using the well-known schemaIDGUID for '$LdapDisplayName'."
    return $Fallback
}

function New-KeyCredentialRule([System.Security.Principal.SecurityIdentifier]$Sid, [Guid]$AttributeGuid,
    [Guid]$UserClass, [bool]$Inherit)
{
    # Grant exactly ReadProperty and WriteProperty on the one attribute; nothing else.
    $rights = [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty, WriteProperty"
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    if ($Inherit)
    {
        $descendants = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
        return [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $Sid, $rights, $allow, $AttributeGuid, $descendants, $UserClass)
    }
    $none = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
    return [System.DirectoryServices.ActiveDirectoryAccessRule]::new($Sid, $rights, $allow, $AttributeGuid, $none)
}

function Test-KeyCredentialRule($Rule, $Expected)
{
    # Match only the explicit rule this helper grants, preserving other scopes and permissions.
    return -not $Rule.IsInherited -and
        $Rule.AccessControlType -eq $Expected.AccessControlType -and
        $Rule.ActiveDirectoryRights -eq $Expected.ActiveDirectoryRights -and
        $Rule.ObjectFlags -eq $Expected.ObjectFlags -and
        $Rule.ObjectType -eq $Expected.ObjectType -and
        $Rule.InheritedObjectType -eq $Expected.InheritedObjectType -and
        $Rule.InheritanceFlags -eq $Expected.InheritanceFlags -and
        $Rule.PropagationFlags -eq $Expected.PropagationFlags -and
        $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq
            $Expected.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
}

function Assert-UnprivilegedTarget([string]$DistinguishedName, [bool]$IsUser, [bool]$Force)
{
    # The write grants authentication as the target, so refuse privileged accounts by default.
    $domain = Get-ADDomain
    $forest = Get-ADDomain -Identity (Get-ADForest).RootDomain
    $privilegedRids = 498, 500, 502, 512, 516, 518, 519, 520, 521, 525, 526, 527
    $privilegedSids = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($rid in $privilegedRids)
    {
        [void]$privilegedSids.Add("$($domain.DomainSID.Value)-$rid")
        [void]$privilegedSids.Add("$($forest.DomainSID.Value)-$rid")
    }
    foreach ($builtin in @("S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551"))
    {
        [void]$privilegedSids.Add($builtin)
    }

    $flagged = [System.Collections.Generic.List[string]]::new()
    $targets = if ($IsUser) { @($DistinguishedName) } else
    {
        Get-ADUser -SearchBase $DistinguishedName -SearchScope Subtree -LDAPFilter "(objectCategory=person)" |
            Select-Object -ExpandProperty DistinguishedName
    }
    foreach ($target in $targets)
    {
        # Read constructed tokenGroups with a per-account query, including every user in an OU.
        $user = Get-ADUser -Identity $target -Properties adminCount, tokenGroups, primaryGroupID, SIDHistory
        if ($user.adminCount -eq 1) { $flagged.Add("$($user.SamAccountName) has adminCount=1") }
        if (-not $user.tokenGroups) { $flagged.Add("$($user.SamAccountName) group membership could not be verified") }
        $accountSid = [System.Security.Principal.SecurityIdentifier]$user.SID
        $primarySid = "$($accountSid.AccountDomainSid.Value)-$($user.primaryGroupID)"
        foreach ($sid in (@($accountSid, $primarySid) + @($user.tokenGroups) + @($user.SIDHistory)))
        {
            if ($null -eq $sid) { continue }
            $value = if ($sid -is [byte[]])
            {
                [System.Security.Principal.SecurityIdentifier]::new($sid, 0).Value
            }
            else { ([System.Security.Principal.SecurityIdentifier]$sid).Value }
            if ($privilegedSids.Contains($value)) { $flagged.Add("$($user.SamAccountName) has privileged SID $value") }
        }
    }

    if ($flagged.Count)
    {
        $detail = $flagged -join "; "
        if (-not $Force)
        {
            throw "Refusing a privileged target ($detail). Delegate over ordinary users only, or pass -Force to override."
        }
        Write-Warn "Proceeding over a privileged target because -Force was supplied: $detail"
    }
}

Write-Host @"
======================================================================
  CRAFT Key Trust (msDS-KeyCredentialLink) Delegation
======================================================================
"@ -ForegroundColor Yellow

Write-Step "Validating environment and resolving identities..."
Import-Module ActiveDirectory -ErrorAction Stop
$rootDse = Get-ADRootDSE -ErrorAction Stop
$schemaNC = $rootDse.schemaNamingContext

$trustee = Resolve-Account $ServiceAccount
$trusteeSid = [System.Security.Principal.SecurityIdentifier]$trustee.SID
Write-Info "Service account : $($trustee.SamAccountName) (SID: $($trusteeSid.Value))"

# Resolve the target object and confirm it is the expected kind for this parameter set.
$defaultContainers = @("CN=Users,", "CN=Computers,", "CN=Managed Service Accounts,")
if ($PSCmdlet.ParameterSetName -eq "OU")
{
    $target = Get-ADObject -Identity $TargetOU -Properties objectClass
    if ($target.objectClass -notin @("organizationalUnit", "container"))
    {
        throw "TargetOU '$TargetOU' is not an Organizational Unit or container."
    }
    $targetDN = $target.DistinguishedName
    $isUser = $false
    $domainDN = (Get-ADDomain).DistinguishedName
    if ($targetDN -eq $domainDN -and -not $Force)
    {
        throw "Refusing to delegate at the domain root. Choose a dedicated OU, or pass -Force to override."
    }
    foreach ($container in $defaultContainers)
    {
        if ($targetDN -like "$container*" -and -not $Force)
        {
            throw "Refusing to delegate over the default container '$targetDN'. Use a dedicated OU, or pass -Force."
        }
    }
    Write-Info "Target OU       : $targetDN (inherited to descendant user objects)"
}
else
{
    $target = Resolve-Account $TargetUser $true
    $targetDN = $target.DistinguishedName
    $isUser = $true
    Write-Info "Target user     : $($target.SamAccountName) ($targetDN)"
}

if (-not $Remove) { Assert-UnprivilegedTarget $targetDN $isUser $Force.IsPresent }

Write-Step "Resolving schema identifiers..."
$attributeGuid = Get-SchemaGuid $schemaNC "msDS-KeyCredentialLink" $KeyCredentialLinkGuid
$userClassGuid = Get-SchemaGuid $schemaNC "user" $UserClassGuid
Write-Info "msDS-KeyCredentialLink : $attributeGuid"

# -----------------------------------------------------------------------------
# Apply or revoke the delegation on the target's security descriptor.
# -----------------------------------------------------------------------------
$aclPath = "AD:\$targetDN"
$acl = Get-Acl -Path $aclPath
$rule = New-KeyCredentialRule $trusteeSid $attributeGuid $userClassGuid (-not $isUser)
$existing = @($acl.Access | Where-Object { Test-KeyCredentialRule $_ $rule })

if ($Remove)
{
    Write-Step "Revoking msDS-KeyCredentialLink delegation from '$($trustee.SamAccountName)'..."
    if (-not $existing.Count)
    {
        Write-Info "No matching delegation found; nothing to remove."
        return
    }
    foreach ($existingRule in $existing)
    {
        [void]$acl.RemoveAccessRuleSpecific($existingRule)
    }
    if ($PSCmdlet.ShouldProcess($targetDN, "Remove msDS-KeyCredentialLink write for $($trustee.SamAccountName)"))
    {
        Set-Acl -Path $aclPath -AclObject $acl
        Write-Info "Delegation removed."
    }
    return
}

Write-Step "Granting msDS-KeyCredentialLink write to '$($trustee.SamAccountName)'..."
if ($existing.Count)
{
    Write-Info "An equivalent delegation already exists; no change made."
    return
}
$acl.AddAccessRule($rule)
if ($PSCmdlet.ShouldProcess($targetDN, "Grant msDS-KeyCredentialLink write to $($trustee.SamAccountName)"))
{
    Set-Acl -Path $aclPath -AclObject $acl
    Write-Info "Delegation granted (ReadProperty, WriteProperty on msDS-KeyCredentialLink only)."
}

Write-Host @"

======================================================================
  SUMMARY
======================================================================
Service account : $($trustee.SamAccountName) ($($trusteeSid.Value))
Target          : $targetDN
Scope           : $(if ($isUser) { "this user object" } else { "descendant user objects" })
Permission      : ReadProperty, WriteProperty on msDS-KeyCredentialLink

This write authorizes Key Trust authentication as the target account(s).
Keep privileged accounts outside the delegated scope and review membership regularly.
Revoke with -Remove. See docs/04-Key-Credential-Link-Delegation.md.
======================================================================
"@ -ForegroundColor Yellow
