<#
.SYNOPSIS
    Configures Active Directory Certificate Services (AD CS) and Active Directory
    for the CRAFT (Certificate Request Agent For Tickets) package.

.DESCRIPTION
    This lab helper configures a CA template and exports starter files for CRAFT.
    CES, configuring CA agent restrictions, full trust/CRL bundles and live validation remain manual:
    1. Creates a Schema Version 2 Certificate Template (default: 'CRAFTUser') with:
       - Extended Key Usages: Smart Card Logon, Client Auth, and PKINIT Client Auth
       - Basic Constraints: CA:FALSE explicitly enabled via msPKI-Enrollment-Flag
       - Issuance Requirements: Mandates 1 Enrollment Agent signature (1.3.6.1.4.1.311.20.2.1)
       - Subject Name: Built from Active Directory (UPN and Common Name)
       - Short Validity: 10-hour certificate lifetime (matching DISA STIG Kerberos user ticket lifetime)
       - RSA-3072 minimum key size
       - Template Security ACL: Adds agent Read/Enroll and removes explicit Authenticated Users Enroll
    2. Registers and assigns a unique template OID in the Active Directory Configuration partition.
    3. Verifies narrow agent/template permissions and CA restrictions before publishing or exporting credentials.
    4. Checks/enrolls a KDC certificate only when run on the selected Domain Controller.
    5. Exports an agent certificate only when running as that agent, or preserves a supplied PFX.
    6. Generates a submitter keytab, CA certificate/CRL, and disabled client configuration.
    Existing submitter passwords may be reset by ktpass; review before running.

.PARAMETER TemplateName
    Name of the certificate template to create (default: 'CRAFTUser').

.PARAMETER TemplateDisplayName
    Display name of the certificate template (default: 'CRAFT User Authentication').

.PARAMETER ValidityHours
    Template validity in hours (1-24, default: 10). Verify that CA backdating fits the client's total-validity cap.

.PARAMETER KeySize
    Key size in bits (3072, matching the worker's generated key).

.PARAMETER EnrollmentAgentIdentity
    Active Directory identity holding the Enrollment Agent certificate (default: 'svc-linux-enroll').

.PARAMETER EnrollmentAgentName
    Requested common name when enrolling as the agent account.

.PARAMETER TargetUser
    Target user account to create or inspect for lab validation (default: 'alice').

.PARAMETER AllowedTargetGroup
    Existing, narrowly scoped security group required in the verified CA enrollment-agent restrictions.

.PARAMETER CAName
    Name of the Enterprise CA (auto-detected only when exactly one is registered).

.PARAMETER KdcHost
    Domain controller DNS name (auto-discovered if not specified).

.PARAMETER CesUrl
    Actual HTTPS CES enrollment endpoint. The script does not install or discover CES.

.PARAMETER ExportPath
    Directory to store exported configuration, certificates, keytabs, and client configuration.

.PARAMETER ExportPassword
    Required SecureString password for the exported agent PFX only; account passwords are generated independently.

.EXAMPLE
    .\Configure-CRAFT-CA.ps1 -AllowedTargetGroup "CRAFT Approved Users" `
        -CesUrl "https://ces.example.com/IssuingCA_CES_Kerberos/service.svc/CES"
    Prompts securely for ExportPassword. Review account password resets and manual setup before use.
#>

[CmdletBinding()]
param(
    [ValidatePattern("^[A-Za-z][A-Za-z0-9_-]{0,63}$")]
    [string]$TemplateName = "CRAFTUser",
    [string]$TemplateDisplayName = "CRAFT User Authentication",
    [ValidateRange(1, 24)]
    [int]$ValidityHours = 10,
    [ValidateSet(3072)]
    [int]$KeySize = 3072,
    [ValidatePattern("^[A-Za-z_][A-Za-z0-9_.-]{0,19}$")]
    [string]$EnrollmentAgentIdentity = "svc-linux-enroll",
    [ValidatePattern("^[A-Za-z0-9 ._-]{1,64}$")]
    [string]$EnrollmentAgentName = "CRAFT Enrollment Agent",
    [ValidatePattern("^[A-Za-z_][A-Za-z0-9_.-]{0,19}$")]
    [string]$TargetUser = "alice",
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$AllowedTargetGroup,
    [string]$CAName = "",
    [string]$KdcHost = "",
    [Parameter(Mandatory)]
    [ValidateScript({ $_.IsAbsoluteUri -and $_.Scheme -eq "https" -and -not $_.UserInfo -and -not $_.Fragment })]
    [uri]$CesUrl,
    [string]$ExportPath = "C:\Setup\Export",
    [Parameter(Mandatory)]
    [ValidateScript({ $_.Length -gt 0 })]
    [System.Security.SecureString]$ExportPassword
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$message)
{
    # Output progress step message
    Write-Host "`n[+] $message" -ForegroundColor Green
}

function Write-Info([string]$message)
{
    # Output informational status message
    Write-Host "    $message" -ForegroundColor Cyan
}

function Write-Warn([string]$message)
{
    # Output warning message
    Write-Host "    [!] $message" -ForegroundColor Yellow
}

function Invoke-CheckedCommand([string]$FilePath, [string[]]$Arguments)
{
    $command = Get-Command $FilePath -CommandType Application -ErrorAction Stop
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try
    {
        & $command.Source @Arguments *>$null
        if (-not $? -or $LASTEXITCODE -ne 0) { throw "$FilePath failed (exit code $LASTEXITCODE)." }
    }
    finally
    {
        $ErrorActionPreference = $previousPreference
    }
}

function Initialize-ExportDirectory([string]$Directory)
{
    if ($Directory -notmatch '^[A-Za-z]:\\') { throw "ExportPath must be an absolute local filesystem path." }
    $fullPath = [System.IO.Path]::GetFullPath($Directory).TrimEnd('\')
    if ($fullPath.Length -le 3) { throw "ExportPath must be a dedicated directory, not a drive root." }
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $callerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $allowed = @($callerSid.Value, 'S-1-5-18', 'S-1-5-32-544')
    $trusted = $allowed + 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    $unsafeRights = [int][System.Security.AccessControl.FileSystemRights]('WriteData,WriteAttributes,' +
        'WriteExtendedAttributes,DeleteSubdirectoriesAndFiles,Delete,ChangePermissions,TakeOwnership') -bor 0x50000000
    $inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly

    $directoryAcl = [System.Security.AccessControl.DirectorySecurity]::new()
    $fileAcl = [System.Security.AccessControl.FileSecurity]::new()
    $directoryAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in $allowed | Select-Object -Unique)
    {
        $identity = [System.Security.Principal.SecurityIdentifier]::new($sid)
        $directoryAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        $fileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', 'Allow'))
    }
    $missing = [System.Collections.Generic.List[string]]::new()

    # Reject paths that another user can replace or redirect before securing their contents.
    for ($parent = [System.IO.DirectoryInfo]::new($fullPath); $null -ne $parent; $parent = $parent.Parent)
    {
        if (-not (Test-Path -LiteralPath $parent.FullName)) { $missing.Add($parent.FullName); continue }
        $item = Get-Item -LiteralPath $parent.FullName -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint))
        {
            throw "ExportPath and its existing parents must be ordinary directories."
        }
        $acl = Get-Acl -LiteralPath $parent.FullName
        if ($acl.GetOwner($sidType).Value -notin $trusted) { throw "ExportPath has an untrusted directory owner." }
        foreach ($rule in $acl.GetAccessRules($true, $true, $sidType))
        {
            if ($rule.AccessControlType -eq 'Allow' -and -not ($rule.PropagationFlags -band $inheritOnly) -and
                $rule.IdentityReference.Value -notin $trusted -and ([int]$rule.FileSystemRights -band $unsafeRights))
            {
                throw "ExportPath has a directory writable or replaceable by another user."
            }
        }
    }
    # Apply private permissions atomically to every newly created path component.
    $missing.Reverse()
    foreach ($directoryPath in $missing)
    {
        if ($PSVersionTable.PSEdition -eq 'Core')
        {
            [System.IO.FileSystemAclExtensions]::CreateDirectory($directoryAcl, $directoryPath) | Out-Null
        }
        else { [System.IO.Directory]::CreateDirectory($directoryPath, $directoryAcl) | Out-Null }
        $item = Get-Item -LiteralPath $directoryPath -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
            (Get-Acl -LiteralPath $directoryPath).GetOwner($sidType).Value -notin $allowed)
        {
            throw "ExportPath changed while its directories were being created."
        }
    }
    $files = @(Get-ChildItem -LiteralPath $fullPath -Force)
    $names = @('agent.pfx', 'submitter.keytab', 'ca.crt', 'ca.crl', 'config', 'krb5.conf', 'template_oid.txt')
    foreach ($file in $files)
    {
        $acl = Get-Acl -LiteralPath $file.FullName
        if ($file.PSIsContainer -or $file.Name -notin $names -or
            ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
            $acl.GetOwner($sidType).Value -notin $allowed)
        {
            throw "ExportPath must contain only ordinary, trusted CRAFT export files."
        }
        foreach ($rule in $acl.GetAccessRules($true, $true, $sidType))
        {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed -and
                ([int]$rule.FileSystemRights -band $unsafeRights))
            {
                throw "Existing export files must not be writable by another user."
            }
        }
    }

    # Protect existing exports as well as files subsequently created by native tools.
    $acl = Get-Acl -LiteralPath $fullPath
    $acl.SetSecurityDescriptorBinaryForm($directoryAcl.GetSecurityDescriptorBinaryForm(), 'Access')
    if ($PSVersionTable.PSEdition -eq 'Core')
    {
        [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.DirectoryInfo]::new($fullPath), $acl)
    }
    else { [System.IO.DirectoryInfo]::new($fullPath).SetAccessControl($acl) }
    foreach ($file in $files)
    {
        $acl = Get-Acl -LiteralPath $file.FullName
        $acl.SetSecurityDescriptorBinaryForm($fileAcl.GetSecurityDescriptorBinaryForm(), 'Access')
        if ($PSVersionTable.PSEdition -eq 'Core')
        {
            [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.FileInfo]::new($file.FullName), $acl)
        }
        else { [System.IO.FileInfo]::new($file.FullName).SetAccessControl($acl) }
    }
    return $fullPath
}

function New-AccountPassword
{
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new(48)
    $password = [System.Security.SecureString]::new()
    try
    {
        $random.GetBytes($bytes)
        foreach ($character in 'Aa1!'.ToCharArray()) { $password.AppendChar($character) }
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        foreach ($value in $bytes) { $password.AppendChar($alphabet[$value -band 63]) }
        $password.MakeReadOnly()
        return $password
    }
    catch { $password.Dispose(); throw }
    finally { [Array]::Clear($bytes, 0, $bytes.Length); $random.Dispose() }
}

function Initialize-CRAFTAccount([string]$Identity, [string]$DnsRoot)
{
    $account = Get-ADUser -Filter { SamAccountName -eq $Identity }
    if ($account) { return $account }
    Write-Info "Creating account '$Identity' with an independent generated password..."
    $password = New-AccountPassword
    try
    {
        New-ADUser -Name $Identity -SamAccountName $Identity -UserPrincipalName "$Identity@$DnsRoot" `
            -AccountPassword $password -Enabled $true -PasswordNeverExpires $true
    }
    finally { $password.Dispose() }
    return Get-ADUser -Identity $Identity
}

function Export-SubmitterKeytab([string]$Principal, [string]$Account, [string]$Path)
{
    if (Test-Path -LiteralPath $Path)
    {
        throw "Refusing to replace an existing submitter keytab or rotate its account key."
    }
    $arguments = @(
        "/princ", $Principal,
        "/mapuser", $Account,
        "/pass", "+rndpass",
        "/minpass", "64", "/maxpass", "64", "/answer", "+",
        "/crypto", "AES256-SHA1",
        "/ptype", "KRB5_NT_PRINCIPAL",
        "/out", $Path
    )
    Invoke-CheckedCommand "ktpass.exe" $arguments
    if (-not (Test-Path -LiteralPath $Path) -or (Get-Item -LiteralPath $Path).Length -eq 0)
    {
        throw "Failed to generate submitter.keytab via ktpass.exe"
    }
}

function Assert-EnrollmentTemplateAcl($Acl, [string]$AgentSid, [string[]]$AdministratorSids, [string]$Name)
{
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Acl.GetSecurityDescriptorBinaryForm(), 0)
    if (-not $descriptor.DiscretionaryAcl -or $Acl.GetOwner($sidType).Value -notin $AdministratorSids)
    {
        throw "Template '$Name' must have an administrator owner and an explicit security descriptor."
    }
    $unsafeWrite = [int][System.DirectoryServices.ActiveDirectoryRights]('WriteDacl,WriteOwner,WriteProperty,' +
        'Self,CreateChild,DeleteChild,Delete,DeleteTree') -bor 0x50000000
    $enrollmentRights = @([Guid]::Empty, [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55',
        [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2')
    foreach ($rule in $Acl.GetAccessRules($true, $true, $sidType))
    {
        if ($rule.AccessControlType -ne 'Allow' -or
            ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        $sid = $rule.IdentityReference.Value
        $rights = [int]$rule.ActiveDirectoryRights
        $canEnroll = ($rights -band 256) -and $rule.ObjectType -in $enrollmentRights
        if ($sid -notin $AdministratorSids -and
            (($rights -band $unsafeWrite) -or ($canEnroll -and $sid -ne $AgentSid)))
        {
            throw "Template '$Name' grants enrollment or modification to '$sid'; restrict it before continuing."
        }
    }
}

function Set-EnrollmentTemplatePermissions([string]$DistinguishedName, [string[]]$AdministratorSids,
    [System.Security.Principal.SecurityIdentifier]$AgentSid, [bool]$RemoveAuthenticatedEnroll)
{
    $path = "AD:$DistinguishedName"
    $acl = Get-Acl -LiteralPath $path
    $enroll = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $sidType = [System.Security.Principal.SecurityIdentifier]
    if ($RemoveAuthenticatedEnroll)
    {
        foreach ($rule in @($acl.GetAccessRules($true, $true, $sidType)))
        {
            if ($rule.IdentityReference.Value -eq 'S-1-5-11' -and $rule.AccessControlType -eq 'Allow' -and
                $rule.ObjectType -eq $enroll)
            {
                if ($rule.IsInherited) { throw "Remove inherited enrollment rights before continuing." }
                $acl.RemoveAccessRuleSpecific($rule)
            }
        }
    }
    Assert-EnrollmentTemplateAcl $acl $AgentSid.Value $AdministratorSids $DistinguishedName
    $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $AgentSid, 'ExtendedRight', 'Allow', $enroll))
    $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new($AgentSid, 'GenericRead', 'Allow'))
    Set-Acl -LiteralPath $path -AclObject $acl
    Assert-EnrollmentTemplateAcl (Get-Acl -LiteralPath $path) $AgentSid.Value $AdministratorSids $DistinguishedName
}

function Assert-EnrollmentAgentRestrictions([byte[]]$Descriptor, [string]$AgentSid, [string]$TargetSid,
    [string[]]$TemplateIdentifiers, [string[]]$OtherAgentSids = @())
{
    if (-not $Descriptor -or $Descriptor.Length -lt 20) { throw "CA enrollment-agent restrictions are absent." }
    $security = [System.Security.AccessControl.RawSecurityDescriptor]::new($Descriptor, 0)
    if (-not $security.DiscretionaryAcl -or $security.DiscretionaryAcl.Count -eq 0)
    {
        throw "CA enrollment-agent restrictions must explicitly allow the CRAFT agent."
    }
    $hasAgentRule = $false
    $unicode = [System.Text.UnicodeEncoding]::new($false, $false, $true)
    foreach ($ace in $security.DiscretionaryAcl)
    {
        if ($ace -isnot [System.Security.AccessControl.CommonAce] -or -not $ace.IsCallback -or
            $ace.AccessMask -ne 0x10000 -or $ace.AceFlags -ne 'None' -or
            $ace.AceQualifier -notin @('AccessAllowed', 'AccessDenied'))
        {
            throw "CA enrollment-agent restrictions contain an unsupported access rule."
        }

        # Decode the MS-CSRA callback payload: SID count, target SIDs and null-terminated UTF-16 template.
        $opaque = $ace.GetOpaque()
        if ($opaque.Length -lt 6 -or ($opaque.Length % 2)) { throw "Invalid enrollment-agent restriction payload." }
        $count = [BitConverter]::ToUInt32($opaque, 0)
        if ($count -gt [Math]::Floor(($opaque.Length - 6) / 8)) { throw "Invalid enrollment-agent target count." }
        $offset = 4
        $targets = [System.Collections.Generic.List[string]]::new()
        for ($index = 0; $index -lt $count; $index++)
        {
            if ($offset + 8 -gt $opaque.Length) { throw "Truncated enrollment-agent target SID." }
            $length = 8 + 4 * $opaque[$offset + 1]
            if ($opaque[$offset] -ne 1 -or $opaque[$offset + 1] -gt 15 -or $offset + $length -gt $opaque.Length - 2)
            {
                throw "Invalid enrollment-agent target SID."
            }
            $target = [System.Security.Principal.SecurityIdentifier]::new($opaque, $offset)
            $targets.Add($target.Value)
            $offset += $length
        }
        $template = $unicode.GetString($opaque, $offset, $opaque.Length - $offset)
        $terminator = $template.IndexOf([char]0)
        if ($terminator -lt 0 -or $template.Substring($terminator).Trim([char]0).Length)
        {
            throw "Invalid enrollment-agent template name."
        }
        $template = $template.Substring(0, $terminator)
        if ($ace.AceQualifier -ne 'AccessAllowed') { continue }
        $trustee = $ace.SecurityIdentifier.Value
        if ($trustee -ne $AgentSid -and $trustee -in $OtherAgentSids) { continue }

        # Group rules can also authorize the agent; require the same narrow scope for every such grant.
        if ($template -notin $TemplateIdentifiers -or $targets.Count -ne 1 -or $targets[0] -ne $TargetSid)
        {
            throw "CA agent Allow rules must specify only the CRAFT template and AllowedTargetGroup."
        }
        if ($trustee -eq $AgentSid) { $hasAgentRule = $true }
    }
    if (-not $hasAgentRule) { throw "CA restrictions must explicitly name the CRAFT agent, template and target group." }
}

function Assert-CAEnrollmentPolicy([string]$Configuration, [string]$AgentSid, [string]$TargetSid,
    [string]$Template, [string]$TemplateOid)
{
    $admin = $null
    try
    {
        $admin = New-Object -ComObject CertificateAuthority.Admin
        [byte[]]$descriptor = $admin.GetConfigEntry($Configuration, '', 'EnrollmentAgentRights')
        $security = [System.Security.AccessControl.RawSecurityDescriptor]::new($descriptor, 0)
        $account = Get-ADUser -Identity $AgentSid -Properties tokenGroups, sIDHistory -ErrorAction Stop
        if (-not $account.tokenGroups) { throw "The agent's transitive authorization groups could not be read." }
        $agentSids = @($AgentSid)
        foreach ($sid in @($account.tokenGroups) + @($account.sIDHistory))
        {
            if ($sid -is [byte[]]) { $agentSids += [System.Security.Principal.SecurityIdentifier]::new($sid, 0).Value }
            elseif ($sid) { $agentSids += ([System.Security.Principal.SecurityIdentifier]$sid).Value }
        }
        $otherAgentSids = @()
        $trustees = @($security.DiscretionaryAcl | ForEach-Object {
            $_.SecurityIdentifier.Value
        } | Select-Object -Unique)
        foreach ($sid in $trustees)
        {
            if ($sid -in $agentSids) { continue }
            try { $account = Get-ADUser -Identity $sid -ErrorAction Stop }
            catch
            {
                $missingIdentity = 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'
                if ($_.Exception.GetType().FullName -ne $missingIdentity) { throw }
                continue
            }
            if ($account.SID.Value -eq $sid -and $account.SID.Value -ne $AgentSid) { $otherAgentSids += $sid }
        }
        $identifiers = @($Template)
        if ($TemplateOid) { $identifiers += $TemplateOid }
        Assert-EnrollmentAgentRestrictions $descriptor $AgentSid $TargetSid $identifiers $otherAgentSids
    }
    catch
    {
        throw "Could not verify restrictions on '$Configuration': $_ Configure the CA Enrollment Agents tab and rerun."
    }
    finally
    {
        if ($admin -and [System.Runtime.InteropServices.Marshal]::IsComObject($admin))
        {
            [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($admin) | Out-Null
        }
    }
}

function Publish-CRAFTTemplates($CA, [string]$Configuration, [string]$Template, [string]$TemplateOid,
    [string]$AgentSid, [string]$TargetSid, [string]$AgentTemplateDN, [string[]]$AdministratorSids)
{
    Assert-CAEnrollmentPolicy $Configuration $AgentSid $TargetSid $Template $TemplateOid
    $identity = [System.Security.Principal.SecurityIdentifier]::new($AgentSid)
    Set-EnrollmentTemplatePermissions $AgentTemplateDN $AdministratorSids $identity $false
    $current = Get-ADObject -Identity $CA.DistinguishedName -Properties certificateTemplates
    $toAdd = [string[]]@(@('EnrollmentAgent', $Template) | Where-Object { $_ -notin $current.certificateTemplates })
    if ($toAdd.Length -gt 0) { Set-ADObject -Identity $CA.DistinguishedName -Add @{ certificateTemplates = $toAdd } }
}

function Get-UsableCertificate([string]$Store, [string]$Eku, [string]$DnsName = "")
{
    $now = Get-Date
    Get-ChildItem -LiteralPath $Store | Where-Object {
        $_.EnhancedKeyUsageList.ObjectId -contains $Eku -and $_.HasPrivateKey -and
        $_.NotBefore -le $now -and $_.NotAfter -gt $now -and
        (-not $DnsName -or $_.DnsNameList.Unicode -contains $DnsName)
    }
}

Write-Host @"
======================================================================
  CRAFT AD CS Automated CA & Template Provisioning Script
======================================================================
"@ -ForegroundColor Yellow

# -----------------------------------------------------------------------------
# 1. Environment & Prerequisite Validation
# -----------------------------------------------------------------------------
Write-Step "Validating environment prerequisites..."

if ($EnrollmentAgentIdentity -ieq $TargetUser)
{
    throw "The service account and target user must be different accounts."
}
Import-Module ActiveDirectory -ErrorAction Stop
$domain = Get-ADDomain -ErrorAction Stop
$rootDse = Get-ADRootDSE -ErrorAction Stop
$configNC = $rootDse.configurationNamingContext

Write-Info "Active Directory Domain : $($domain.DNSRoot) (NetBIOS: $($domain.NetBIOSName))"
Write-Info "Configuration Naming Context: $configNC"

# Auto-discover CA name if not provided
$caEntries = @(Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" `
    -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC" `
    -Properties dNSHostName, certificateTemplates)
if ($CAName) { $caEntries = @($caEntries | Where-Object { $_.Name -eq $CAName }) }
if ($caEntries.Count -ne 1 -or -not $caEntries[0].dNSHostName)
{
    throw "Specify a CAName identifying exactly one registered Enterprise CA with a DNS host name."
}
$caObj = $caEntries[0]
$CAName = $caObj.Name
$caHost = $caObj.dNSHostName
$caConfig = "$caHost\$CAName"
if (-not $KdcHost) { $KdcHost = (Get-ADDomainController -Discover -Service KDC).HostName }
$kdc = Get-ADDomainController -Identity $KdcHost
$KdcHost = $kdc.HostName
$targetGroup = Get-ADGroup -Identity $AllowedTargetGroup
if ($targetGroup.GroupCategory -ne "Security") { throw "AllowedTargetGroup must be a security group." }
$AllowedTargetGroup = $targetGroup.Name
foreach ($command in @("ktpass.exe", "certreq.exe", "certutil.exe"))
{
    Get-Command $command -CommandType Application -ErrorAction Stop | Out-Null
}
$keytabPath = Join-Path $ExportPath "submitter.keytab"
if (Test-Path -LiteralPath $keytabPath)
{
    throw "submitter.keytab already exists. Preserve it or choose a new ExportPath before rotating account keys."
}
Write-Info "Certification Authority     : $CAName ($caConfig)"

$ExportPath = Initialize-ExportDirectory $ExportPath

# -----------------------------------------------------------------------------
# 2. Ensure Service Account & Target User Exist
# -----------------------------------------------------------------------------
Write-Step "Configuring Active Directory accounts..."

# Submitter / Enrollment Agent service account
$agentUser = Initialize-CRAFTAccount $EnrollmentAgentIdentity $domain.DNSRoot
Write-Info "Enrollment Agent Account    : $($agentUser.UserPrincipalName) (SID: $($agentUser.SID))"

# Target user for demonstration / testing
$userObj = Initialize-CRAFTAccount $TargetUser $domain.DNSRoot
Write-Info "Target Demo User            : $($userObj.UserPrincipalName) (SID: $($userObj.SID))"

# -----------------------------------------------------------------------------
# 3. Create and Configure Schema V2 CRAFT Certificate Template
# -----------------------------------------------------------------------------
Write-Step "Configuring Certificate Template '$TemplateName'..."

$templatesDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$templateContainer = [ADSI]"LDAP://$templatesDN"
$templateLdapPath = "LDAP://CN=$TemplateName,$templatesDN"

$agentSid = $agentUser.SID
$forestRoot = Get-ADDomain -Identity (Get-ADForest).RootDomain
$administratorSids = @('S-1-5-18', 'S-1-5-32-544', "$($domain.DomainSID.Value)-512",
    "$($forestRoot.DomainSID.Value)-512", "$($forestRoot.DomainSID.Value)-518", "$($forestRoot.DomainSID.Value)-519")
$caller = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if (@($caller.Groups.Value | Where-Object { $_ -in $administratorSids -and $_ -like 'S-1-5-21-*' }).Count)
{
    $administratorSids += $caller.User.Value
}
$agentTemplateDN = "CN=EnrollmentAgent,$templatesDN"
$agentTemplateAcl = Get-Acl -LiteralPath "AD:$agentTemplateDN"
Assert-EnrollmentTemplateAcl $agentTemplateAcl $agentSid.Value $administratorSids 'EnrollmentAgent'

$templateExists = [ADSI]::Exists($templateLdapPath)
if ($templateExists)
{
    Write-Info "Existing template '$TemplateName' found; updating configuration..."
    $tmpl = [ADSI]$templateLdapPath
    Assert-CAEnrollmentPolicy $caConfig $agentSid.Value $targetGroup.SID.Value $TemplateName `
        $tmpl.Properties['msPKI-Cert-Template-OID'].Value
    Set-EnrollmentTemplatePermissions "CN=$TemplateName,$templatesDN" $administratorSids $agentSid $true
}
else
{
    Write-Info "Creating new pKICertificateTemplate object 'CN=$TemplateName'..."

    # Source template attributes from SmartcardLogon
    $src = [ADSI]"LDAP://CN=SmartcardLogon,$templatesDN"
    $tmpl = $templateContainer.Create("pKICertificateTemplate", "CN=$TemplateName")
    
    foreach ($prop in @("flags", "revision", "msPKI-Certificate-Name-Flag", 
                       "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag"))
    {
        if ($null -ne $src.Properties[$prop].Value)
        {
            $tmpl.Put($prop, $src.Properties[$prop].Value)
        }
    }
}

# General Properties
$tmpl.Put("displayName", $TemplateDisplayName)
$tmpl.Put("msPKI-Template-Schema-Version", 2)
$minorRevision = [int]$tmpl.Properties["msPKI-Template-Minor-Revision"].Value
$tmpl.Put("msPKI-Template-Minor-Revision", $minorRevision + 1)
$tmpl.Put("msPKI-Minimal-Key-Size", $KeySize)

# Validity Period (negative 100-nanosecond intervals)
# e.g., 4 hours = 4 * 3600 * 10,000,000 = 144,000,000,000
$validityInterval = -[long]($ValidityHours * 3600 * 10000000L)
$tmpl.Put("pkiExpirationPeriod", [BitConverter]::GetBytes($validityInterval))

# Renewal overlap is 10% of validity; CRAFT performs initial enrollment, not auto-renewal.
$overlapInterval = [long]($validityInterval / 10)
$tmpl.Put("pkiOverlapPeriod", [BitConverter]::GetBytes($overlapInterval))

# EKUs: Smart Card Logon, Client Authentication, PKINIT Client Authentication
# CRAFT worker requires all three in leaf certificate validation
$ekus = @(
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "1.3.6.1.5.5.7.3.2",        # Client Authentication
    "1.3.6.1.5.2.3.4"           # PKINIT Client Authentication
)
$tmpl.PutEx(2, "pKIExtendedKeyUsage", $ekus)
$tmpl.PutEx(2, "msPKI-Certificate-Application-Policy", $ekus)

# Schema Version 2 required attributes
$tmpl.Put("msPKI-Private-Key-Flag", 0)
$tmpl.Put("pKIDefaultKeySpec", 1)
$tmpl.PutEx(2, "pKIDefaultCSPs", @("1,Microsoft RSA SChannel Cryptographic Provider"))

# Key Usage: Digital Signature (0x80) + Key Encipherment (0x20) = 0xA0
$tmpl.Put("pKIKeyUsage", [byte[]]@(0xA0, 0x00))

# Critical: CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS (0x8000 = 32768)
# CT_FLAG_PEND_ALL_REQUESTS (0x0002) is omitted to allow automatic issuance
$enrollmentFlag = 0x8000
$tmpl.Put("msPKI-Enrollment-Flag", $enrollmentFlag)

# Subject Name: Built from Active Directory (Never supply in request!)
# CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH (0x80000000)
# CT_FLAG_SUBJECT_ALT_REQUIRE_UPN (0x02000000 = 33554432)
# 0x82000000 = -2113929216 as signed 32-bit int
$nameFlag = [int]-2113929216
$tmpl.Put("msPKI-Certificate-Name-Flag", $nameFlag)

# Issuance Requirements: Mandate 1 Authorized Enrollment Agent Signature
$tmpl.Put("msPKI-RA-Signature", 1)
$tmpl.PutEx(2, "msPKI-RA-Application-Policies", @("1.3.6.1.4.1.311.20.2.1")) # Certificate Request Agent

# Register Template OID and msPKI-Enterprise-Oid object in AD
$oidContainerDN = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
$existingOid = $tmpl.Properties["msPKI-Cert-Template-OID"].Value
if (-not $existingOid)
{
    # Append a random 128-bit suffix to the forest's registered OID prefix.
    $basePrefix = (Get-ADObject -Identity $oidContainerDN `
        -Properties "msPKI-Cert-Template-OID")."msPKI-Cert-Template-OID"
    if (-not $basePrefix) { throw "The forest enterprise OID prefix is missing." }
    do
    {
        $oidBytes = [Guid]::NewGuid().ToByteArray()
        $suffix = (0, 4, 8, 12 | ForEach-Object { [BitConverter]::ToUInt32($oidBytes, $_) }) -join "."
        $newOid = "$basePrefix.$suffix"
    }
    while (Get-ADObject -Filter { msPKI-Cert-Template-OID -eq $newOid } -SearchBase $oidContainerDN)
    $tmpl.Put("msPKI-Cert-Template-OID", $newOid)
    Write-Info "Derived template OID: $newOid"
}
else
{
    $newOid = $existingOid
    Write-Info "Retaining template OID: $newOid"
}

# Ensure msPKI-Enterprise-Oid object exists in CN=OID for CA policy module
$existingOidObj = Get-ADObject -Filter { msPKI-Cert-Template-OID -eq $newOid } -SearchBase $oidContainerDN
if (-not $existingOidObj)
{
    $guidHex = [Guid]::NewGuid().ToString("N").ToUpper()
    $oidCN = "100.$guidHex"
    New-ADObject -Name $oidCN `
                 -Type "msPKI-Enterprise-Oid" `
                 -Path $oidContainerDN `
                 -OtherAttributes @{
                     "DisplayName" = $TemplateDisplayName;
                     "flags" = 1;
                     "msPKI-Cert-Template-OID" = $newOid
                 } | Out-Null
    Write-Info "Registered Enterprise OID object: $oidCN"
}

# Commit template changes
$tmpl.SetInfo()
Write-Info "Template '$TemplateName' saved to Active Directory."

# Write template OID to export file for CRAFT
$newOid | Set-Content -Path (Join-Path $ExportPath "template_oid.txt") -Encoding ASCII

# -----------------------------------------------------------------------------
# 4. Configure Security Permissions (ACL) on Templates
# -----------------------------------------------------------------------------
Write-Step "Configuring narrow template permissions for '$EnrollmentAgentIdentity'..."

Set-EnrollmentTemplatePermissions "CN=$TemplateName,$templatesDN" $administratorSids $agentSid $true

# -----------------------------------------------------------------------------
# 5. Verify CA Restrictions and Publish Templates
# -----------------------------------------------------------------------------
Write-Step "Verifying CA restrictions before publishing templates on '$CAName'..."

Publish-CRAFTTemplates $caObj $caConfig $TemplateName $newOid $agentSid.Value $targetGroup.SID.Value `
    $agentTemplateDN $administratorSids
Write-Info "Verified restrictions for '$EnrollmentAgentIdentity', '$TemplateName' and '$AllowedTargetGroup'."

# -----------------------------------------------------------------------------
# 6. Export Submitter Kerberos Keytab
# -----------------------------------------------------------------------------
Write-Step "Generating Kerberos keytab for $EnrollmentAgentIdentity..."

$realmUpper = $domain.DNSRoot.ToUpperInvariant()
Export-SubmitterKeytab "$EnrollmentAgentIdentity@$realmUpper" `
    "$($domain.NetBIOSName)\$EnrollmentAgentIdentity" $keytabPath
Write-Info "Keytab generated successfully at $keytabPath"

# -----------------------------------------------------------------------------
# 7. Ensure KDC Certificate for Kerberos PKINIT
# -----------------------------------------------------------------------------
Write-Step "Checking Domain Controller KDC certificate..."

if ($kdc.Name -ine $env:COMPUTERNAME)
{
    Write-Warn "Verify a current KDC certificate with a private key on $KdcHost; this host is not that DC."
}
else
{
    $kdcEku = "1.3.6.1.5.2.3.5" # KDC Authentication
    $existingKdcCert = Get-UsableCertificate "Cert:\LocalMachine\My" $kdcEku $KdcHost | Select-Object -First 1
    if (-not $existingKdcCert)
    {
        Invoke-CheckedCommand "certutil.exe" @("-config", $caConfig, "-SetCATemplates", "+KerberosAuthentication")
        Invoke-CheckedCommand "certreq.exe" @(
            "-enroll", "-machine", "-q", "-config", $caConfig, "KerberosAuthentication")
        $existingKdcCert = Get-UsableCertificate "Cert:\LocalMachine\My" $kdcEku $KdcHost | Select-Object -First 1
        if (-not $existingKdcCert) { throw "KDC enrollment did not yield a current certificate with a private key." }
        Restart-Service -Name Kdc -Force
    }
    Write-Info "Current KDC certificate: $($existingKdcCert.Subject) (Expires: $($existingKdcCert.NotAfter))"
}

# -----------------------------------------------------------------------------
# 8. Request & Export Enrollment Agent Certificate
# -----------------------------------------------------------------------------
Write-Step "Generating Enrollment Agent certificate for CRAFT..."

$pfxPath = Join-Path $ExportPath "agent.pfx"

if (Test-Path -LiteralPath $pfxPath)
{
    if ((Get-Item -LiteralPath $pfxPath).Length -eq 0) { throw "The supplied agent.pfx is empty." }
    Write-Info "Preserving existing agent credentials: $pfxPath"
}
elseif ([System.Security.Principal.WindowsIdentity]::GetCurrent().User -eq $agentUser.SID)
{
    $agentCerts = @(Get-UsableCertificate "Cert:\CurrentUser\My" "1.3.6.1.4.1.311.20.2.1")
    if ($agentCerts.Count -gt 1) { throw "Multiple agent certificates found; export the intended agent.pfx manually." }
    $agentCert = $agentCerts | Select-Object -First 1

    if (-not $agentCert)
    {
        Write-Info "Enrolling new Enrollment Agent certificate..."
        $eaInf = @"
[NewRequest]
Subject = "CN=$EnrollmentAgentName,DC=$($domain.DNSRoot.Replace('.', ',DC='))"
KeyLength = $KeySize
KeySpec = 1
KeyUsage = 0xA0
Exportable = True
ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
RequestType = CMC
[RequestAttributes]
CertificateTemplate = "EnrollmentAgent"
"@
        $requestName = "craft-agent-$([Guid]::NewGuid().ToString('N'))"
        $eaInfPath = Join-Path $env:TEMP "$requestName.inf"
        $eaReqPath = Join-Path $env:TEMP "$requestName.req"
        $eaCerPath = Join-Path $env:TEMP "$requestName.cer"
        $eaInf | Set-Content -Path $eaInfPath -Encoding ASCII

        try
        {
            Invoke-CheckedCommand "certreq.exe" @("-new", "-q", $eaInfPath, $eaReqPath)
            Invoke-CheckedCommand "certreq.exe" @("-submit", "-q", "-config", $caConfig, $eaReqPath, $eaCerPath)
            Invoke-CheckedCommand "certreq.exe" @("-accept", "-q", $eaCerPath)
            $issuedCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($eaCerPath)
            try { $agentCert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$($issuedCert.Thumbprint)" }
            finally { $issuedCert.Dispose() }
        }
        finally
        {
            Remove-Item -LiteralPath $eaInfPath, $eaReqPath, $eaCerPath -Force -ErrorAction SilentlyContinue
        }
    }

    if ($agentCert -and $agentCert.HasPrivateKey -and $agentCert.NotAfter -gt (Get-Date) -and
        $agentCert.NotBefore -le (Get-Date) -and
        $agentCert.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.4.1.311.20.2.1")
    {
        $pfxBytes = $agentCert.Export(
            [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $ExportPassword)
        [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
        Write-Info "Exported agent.pfx to $pfxPath"
    }
    else
    {
        throw "Enrollment did not yield a usable agent certificate with a private key."
    }
}
else
{
    Write-Warn "Supply agent.pfx enrolled as '$EnrollmentAgentIdentity'; certreq would enroll as the invoking account."
}

# -----------------------------------------------------------------------------
# 9. Export CA Certificate and CRL
# -----------------------------------------------------------------------------
Write-Step "Exporting CA trust certificate and revocation list (CRL)..."

$caCrtPath = Join-Path $ExportPath "ca.crt"
$caCrlPath = Join-Path $ExportPath "ca.crl"

Invoke-CheckedCommand "certutil.exe" @("-f", "-config", $caConfig, "-ca.cert", $caCrtPath)
Invoke-CheckedCommand "certutil.exe" @("-f", "-config", $caConfig, "-getCRL", $caCrlPath)
foreach ($exportedFile in @($caCrtPath, $caCrlPath))
{
    if (-not (Test-Path -LiteralPath $exportedFile) -or (Get-Item -LiteralPath $exportedFile).Length -eq 0)
    {
        throw "CA export did not produce $exportedFile."
    }
}
Write-Info "Exported CA Certificate : $caCrtPath"
Write-Info "Exported CA CRL         : $caCrlPath"

# -----------------------------------------------------------------------------
# 10. Generate Linux Client Configuration (config)
# -----------------------------------------------------------------------------
Write-Step "Generating Linux client configuration ($ExportPath\config)..."

$craftConfContent = @"
enabled=no
domain=$($domain.DNSRoot)
realm=$realmUpper
netbios=$($domain.NetBIOSName)
template_oid=$newOid
certificate_cn={user}
ces_url=$($CesUrl.AbsoluteUri)
ces_auth=negotiate
service_principal=$EnrollmentAgentIdentity@$realmUpper
tgt_seconds=36000
renew_seconds=604800
require_full_tgt_lifetime=yes
cert_remaining_max_seconds=$($ValidityHours * 3600)
cert_total_max_seconds=$($ValidityHours * 3600)
minimum_interval_seconds=60
"@

$craftConfPath = Join-Path $ExportPath "config"
$craftConfContent | Set-Content -Path $craftConfPath -Encoding ASCII

Write-Info "Exported client configuration to $craftConfPath"

$krb5ConfContent = @"
[libdefaults]
    default_realm = $realmUpper
    dns_lookup_realm = false
    dns_lookup_kdc = false
    dns_canonicalize_hostname = false
    rdns = false
    allow_weak_crypto = false
    forwardable = false
    proxiable = false
    ticket_lifetime = 10h
    renew_lifetime = 7d
    kdc_default_options = 0
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    udp_preference_limit = 1

[realms]
    $realmUpper = {
        kdc = $KdcHost
        default_domain = $($domain.DNSRoot)
        pkinit_anchors = FILE:/etc/craft/kdc-trust.pem
        pkinit_pool = FILE:/etc/craft/ca-trust.pem
        pkinit_revoke = FILE:/etc/craft/kdc-crls.pem
        pkinit_require_crl_checking = true
        pkinit_eku_checking = kpKDC
        pkinit_kdc_hostname = $KdcHost
    }

[domain_realm]
    .$($domain.DNSRoot) = $realmUpper
    $($domain.DNSRoot) = $realmUpper
"@

$krb5ConfPath = Join-Path $ExportPath "krb5.conf"
$krb5ConfContent | Set-Content -Path $krb5ConfPath -Encoding ASCII
Write-Info "Exported krb5.conf to $krb5ConfPath"

# -----------------------------------------------------------------------------
# 11. Security Hardening & Enrollment Agent Restrictions Summary
# -----------------------------------------------------------------------------
Write-Host @"

======================================================================
  CONFIGURATION SUMMARY & VERIFIED CA RESTRICTIONS
======================================================================
Active Directory Template : $TemplateName
Template OID              : $newOid
Validity Period           : $ValidityHours Hours
Basic Constraints         : CA:FALSE (CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS)
Required RA Signatures    : 1 (Policy: Certificate Request Agent)
Subject Name Setting      : Built from Active Directory (UPN + CN)
Enrollment Agent Account  : $EnrollmentAgentIdentity@$($domain.DNSRoot)
Demo Target User          : $TargetUser@$($domain.DNSRoot)
Export Directory          : $ExportPath

Verified CA enrollment-agent configuration:
   Enrollment Agent : '$EnrollmentAgentIdentity'
   Templates        : '$TemplateName' only
   Target Users     : '$AllowedTargetGroup' only
Keep target-group membership narrowly scoped and exclude privileged accounts.

Starter files have been written to '$ExportPath'; client enrollment remains disabled.
Confirm agent.pfx belongs to the restricted agent, and provision full PEM trust/CRL bundles.
Configure CES/SPNs and verify actual certificate backdating and KDC ticket lifetime before enabling.
======================================================================
"@ -ForegroundColor Yellow

