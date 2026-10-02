# Offline checks only: extract helpers without executing top-level provisioning commands.
$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "Configure-CRAFT-CA.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors.Message -join "`n") }

foreach ($name in @("Invoke-CheckedCommand", "Get-UsableCertificate", "Initialize-ExportDirectory",
    "New-AccountPassword", "Initialize-CRAFTAccount", "Export-SubmitterKeytab", "Assert-EnrollmentTemplateAcl",
    "Set-EnrollmentTemplatePermissions", "Assert-EnrollmentAgentRestrictions", "Assert-CAEnrollmentPolicy",
    "Publish-CRAFTTemplates"))
{
    $definition = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $false)
    if (-not $definition) { throw "Missing helper: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Assert([bool]$Condition, [string]$Message)
{
    if (-not $Condition) { throw $Message }
}

& {
    $root = Join-Path $env:USERPROFILE "CRAFT.Tests.$([Guid]::NewGuid().ToString('N'))"
    [System.IO.Directory]::CreateDirectory($root) | Out-Null
    try
    {
        $users = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $acl = Get-Acl -LiteralPath $root
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $users, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        Set-Acl -LiteralPath $root -AclObject $acl
        $directory = Join-Path $root 'Export'
        [System.IO.Directory]::CreateDirectory($directory) | Out-Null
        $pfx = Join-Path $directory 'agent.pfx'
        [System.IO.File]::WriteAllText($pfx, 'SYNTHETIC-NO-CREDENTIALS')
        Assert (@((Get-Acl -LiteralPath $pfx).Access | Where-Object {
            $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $users
        }).Count -gt 0) "ACL fixture did not inherit ordinary Users access."
        Assert ((Initialize-ExportDirectory $directory) -eq $directory) "Export path unexpectedly changed."
        $keytab = Join-Path $directory 'submitter.keytab'
        [System.IO.File]::WriteAllText($keytab, 'SYNTHETIC-NO-CREDENTIALS')
        Initialize-ExportDirectory $directory | Out-Null
        $allowed = @([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
            'S-1-5-18', 'S-1-5-32-544')
        foreach ($path in @($directory, $pfx, $keytab))
        {
            foreach ($rule in (Get-Acl -LiteralPath $path).GetAccessRules(
                $true, $true, [System.Security.Principal.SecurityIdentifier]))
            {
                Assert ($rule.IdentityReference.Value -in $allowed) "Export retained unauthorized file access."
            }
        }
        Assert ([System.IO.File]::ReadAllText($pfx) -eq 'SYNTHETIC-NO-CREDENTIALS') "Existing PFX was changed."
        $fresh = Join-Path $root 'Fresh\Nested'
        Initialize-ExportDirectory $fresh | Out-Null
        foreach ($path in @((Split-Path -Parent $fresh), $fresh))
        {
            $acl = Get-Acl -LiteralPath $path
            Assert $acl.AreAccessRulesProtected "A newly created export parent inherited broad access."
            foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
            {
                Assert ($rule.IdentityReference.Value -in $allowed) "A newly created export parent is not private."
            }
        }
        $junction = Join-Path $root 'Redirect'
        New-Item -ItemType Junction -Path $junction -Target $directory | Out-Null
        $rejected = $false
        try { Initialize-ExportDirectory (Join-Path $junction 'Nested') | Out-Null }
        catch { $rejected = $true }
        Assert $rejected "Export followed a junction in a parent directory."
        [System.IO.Directory]::Delete($junction)
        $acl = Get-Acl -LiteralPath $root
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $users, 'Modify', 'None', 'None', 'Allow'))
        Set-Acl -LiteralPath $root -AclObject $acl
        $rejected = $false
        try { Initialize-ExportDirectory $directory | Out-Null }
        catch { $rejected = $true }
        Assert $rejected "Export accepted a directory replaceable by ordinary Users."
    }
    finally
    {
        if ([System.IO.Path]::GetDirectoryName($root) -ne $env:USERPROFILE -or
            [System.IO.Path]::GetFileName($root) -notlike 'CRAFT.Tests.*') { throw "Unexpected ACL fixture path." }
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
Write-Host "PASS: export ACL isolation, existing credentials and unsafe parent rejection"

$parameterCheck = [scriptblock]::Create($ast.ParamBlock.Extent.Text + "`n" +
    '[pscustomobject]@{ ValidityHours = $ValidityHours; KeySize = $KeySize; CesUrl = $CesUrl }')
$valid = @{ AllowedTargetGroup = "CRAFT Test Users"; ExportPassword = (ConvertTo-SecureString "offline-test-only" -AsPlainText -Force);
    CesUrl = "https://ces.example.com/service.svc/CES" }
$defaults = & $parameterCheck @valid
Assert ($defaults.ValidityHours -eq 10 -and $defaults.KeySize -eq 3072) "Unexpected certificate defaults."
foreach ($case in @(
    @{ ValidityHours = 0 }, @{ ValidityHours = 25 }, @{ KeySize = 2048 }, @{ KeySize = 4096 },
    @{ TemplateName = "Invalid,Name" }, @{ EnrollmentAgentIdentity = "bad'user" },
    @{ TargetUser = "bad(user)" }, @{ EnrollmentAgentName = 'bad"name' },
    @{ CesUrl = "http://ces.example.com/" }, @{ CesUrl = "/relative" },
    @{ CesUrl = "https://user@ces.example.com/" }, @{ CesUrl = "https://ces.example.com/#fragment" },
    @{ AllowedTargetGroup = "" }, @{ ExportPassword = [System.Security.SecureString]::new() }
))
{
    $parameters = $valid.Clone()
    foreach ($key in $case.Keys) { $parameters[$key] = $case[$key] }
    $rejected = $false
    try { & $parameterCheck @parameters | Out-Null }
    catch [System.Management.Automation.ParameterBindingException] { $rejected = $true }
    Assert $rejected "Invalid provisioning input was accepted: $($case.Keys -join ', ')."
}
Write-Host "PASS: provisioning parameter validation"

& {
    # Execute only the client export block, with synthetic directory and domain data.
    $start = $ast.EndBlock.Statements | Where-Object {
        $_.Extent.Text -like 'Write-Step "Generating Linux client configuration*'
    } | Select-Object -First 1
    $end = $ast.EndBlock.Statements | Where-Object {
        $_.Extent.Text -like 'Write-Info "Exported krb5.conf*'
    } | Select-Object -First 1
    Assert ($null -ne $start -and $null -ne $end) "Missing client configuration export block."
    $export = [scriptblock]::Create($ast.Extent.Text.Substring(
        $start.Extent.StartOffset, $end.Extent.EndOffset - $start.Extent.StartOffset))
    function Write-Step([string]$Message) {}
    function Write-Info([string]$Message) {}
    $domain = [pscustomobject]@{ DNSRoot = 'example.com'; NetBIOSName = 'EXAMPLE' }
    $realmUpper = 'EXAMPLE.COM'
    $newOid = '1.3.6.1.4.1.311.21.8.999.1'
    $EnrollmentAgentIdentity = 'svc-offline-test'
    $CesUrl = [uri]'https://ces.example.com/service.svc/CES'
    $KdcHost = 'dc.example.com'
    $ExportPath = Join-Path $env:USERPROFILE "CRAFT.Tests.$([Guid]::NewGuid().ToString('N'))"
    [System.IO.Directory]::CreateDirectory($ExportPath) | Out-Null
    try
    {
        foreach ($case in @(@(1, 1), @(4, 4), @(9, 9), @(10, 10), @(11, 10), @(24, 10)))
        {
            $ValidityHours = $case[0]
            & $export
            $config = ConvertFrom-StringData ([System.IO.File]::ReadAllText((Join-Path $ExportPath 'config')))
            $krb5 = [System.IO.File]::ReadAllText((Join-Path $ExportPath 'krb5.conf'))
            $ticket = [regex]::Match($krb5, '(?m)^\s*ticket_lifetime\s*=\s*(\d+)h\s*$')
            Assert ($ticket.Success -and [int]$ticket.Groups[1].Value -eq $case[1]) `
                "Kerberos ticket lifetime is incompatible with a $ValidityHours-hour certificate."
            Assert ([int]$config.tgt_seconds -eq $case[1] * 3600) "CRAFT and Kerberos ticket lifetimes differ."
            Assert ([int]$config.cert_remaining_max_seconds -eq $ValidityHours * 3600 -and
                [int]$config.cert_total_max_seconds -eq $ValidityHours * 3600) "Certificate validity caps differ."
            Assert ($config.enabled -eq 'no' -and $config.require_full_tgt_lifetime -eq 'yes' -and
                $config.renew_seconds -eq '604800' -and $krb5 -match '(?m)^\s*renew_lifetime\s*=\s*7d\s*$') `
                "Generated client configuration lost its strict lifetime or renewal policy."
        }
    }
    finally
    {
        if ([System.IO.Path]::GetDirectoryName($ExportPath) -ne $env:USERPROFILE -or
            [System.IO.Path]::GetFileName($ExportPath) -notlike 'CRAFT.Tests.*') { throw "Unexpected export fixture path." }
        Remove-Item -LiteralPath $ExportPath -Recurse -Force
    }
}
Write-Host "PASS: exported client lifetimes match short and default certificate validity"

& {
    $accounts = @{}
    $passwords = @{}
    function Write-Info([string]$Message) {}
    function Get-ADUser([scriptblock]$Filter, [Alias('Identity')][string]$LookupIdentity)
    {
        if ($Filter) { $LookupIdentity = (Get-Variable -Name Identity -Scope 1).Value }
        $accounts[$LookupIdentity]
    }
    function New-ADUser([string]$Name, [string]$SamAccountName, [string]$UserPrincipalName,
        [System.Security.SecureString]$AccountPassword, [bool]$Enabled, [bool]$PasswordNeverExpires)
    {
        Assert ($Name -eq $SamAccountName -and $Enabled) "Unexpected account creation parameters."
        Assert ($AccountPassword.IsReadOnly() -and $AccountPassword.Length -ge 48) "Weak generated account password."
        $passwords[$Name] = $AccountPassword.Copy()
        $accounts[$Name] = [pscustomobject]@{ UserPrincipalName = $UserPrincipalName; SID = $Name }
    }
    try
    {
        $service = Initialize-CRAFTAccount 'svc-test' 'example.com'
        $demo = Initialize-CRAFTAccount 'demo-test' 'example.com'
        $serviceSecret = [System.Net.NetworkCredential]::new('', $passwords['svc-test']).Password
        $demoSecret = [System.Net.NetworkCredential]::new('', $passwords['demo-test']).Password
        Assert ($serviceSecret -match '^Aa1![A-Za-z0-9+/]{48}$') "Unexpected account password format."
        Assert ($serviceSecret -ne $demoSecret -and $serviceSecret -ne 'offline-test-only' -and
            $demoSecret -ne 'offline-test-only') "Service, demo and PFX credentials were reused."
        $existing = Initialize-CRAFTAccount 'svc-test' 'example.com'
        Assert ($existing -eq $service -and $passwords.Count -eq 2) "An existing account's password was reset."
        Assert ($demo.UserPrincipalName -eq 'demo-test@example.com') "Demo account identity changed."
    }
    finally { foreach ($password in $passwords.Values) { $password.Dispose() } }
}
Write-Host "PASS: independently generated account passwords and existing account preservation"

& {
    $root = Join-Path $env:USERPROFILE "CRAFT.Tests.$([Guid]::NewGuid().ToString('N'))"
    Initialize-ExportDirectory $root | Out-Null
    $path = Join-Path $root 'submitter.keytab'
    $calls = [System.Collections.Generic.List[object]]::new()
    $writeEmpty = $false
    function Invoke-CheckedCommand([string]$FilePath, [string[]]$Arguments)
    {
        Assert ($FilePath -eq 'ktpass.exe') "Unexpected keytab generator."
        $calls.Add($Arguments)
        $output = $Arguments[[Array]::IndexOf($Arguments, '/out') + 1]
        [System.IO.File]::WriteAllText($output, $(if ($writeEmpty) { '' } else { 'SYNTHETIC-NO-CREDENTIALS' }))
    }
    try
    {
        Export-SubmitterKeytab 'svc-test@EXAMPLE.COM' 'EXAMPLE\svc-test' $path
        $expected = @('/princ', 'svc-test@EXAMPLE.COM', '/mapuser', 'EXAMPLE\svc-test',
            '+rndpass', '/minpass', '64', '/maxpass', '64', '+answer',
            '/crypto', 'AES256-SHA1', '/ptype', 'KRB5_NT_PRINCIPAL', '/out', $path)
        $matches = $calls.Count -eq 1 -and ($calls[0] -join '|') -ceq ($expected -join '|')
        Assert $matches "Keytab generation exposed a password or changed its principal/encryption."
        $rejected = $false
        try { Export-SubmitterKeytab 'svc-test@EXAMPLE.COM' 'EXAMPLE\svc-test' $path }
        catch { $rejected = $true }
        Assert ($rejected -and $calls.Count -eq 1) "An existing keytab was overwritten or its password rotated."
        Remove-Item -LiteralPath $path -Force
        $writeEmpty = $true
        $rejected = $false
        try { Export-SubmitterKeytab 'svc-test@EXAMPLE.COM' 'EXAMPLE\svc-test' $path }
        catch { $rejected = $true }
        Assert $rejected "Empty keytab output was accepted."
    }
    finally
    {
        if ([System.IO.Path]::GetDirectoryName($root) -ne $env:USERPROFILE -or
            [System.IO.Path]::GetFileName($root) -notlike 'CRAFT.Tests.*') { throw "Unexpected keytab fixture path." }
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
Write-Host "PASS: secret-free keytab invocation, overwrite prevention and empty-output rejection"

& {
    $agent = 'S-1-5-21-1-2-3-1001'
    $target = 'S-1-5-21-1-2-3-1002'
    $other = 'S-1-5-21-1-2-3-1003'
    function New-RestrictionAce([string]$Trustee = $agent, [string[]]$Targets = @($target),
        [string]$Template = 'CRAFTUser', [int]$Mask = 0x10000, [bool]$Callback = $true)
    {
        $bytes = [System.Collections.Generic.List[byte]]::new()
        $bytes.AddRange([BitConverter]::GetBytes([uint32]$Targets.Count))
        foreach ($sid in $Targets)
        {
            $identity = [System.Security.Principal.SecurityIdentifier]::new($sid)
            $binary = [byte[]]::new($identity.BinaryLength)
            $identity.GetBinaryForm($binary, 0)
            $bytes.AddRange($binary)
        }
        $bytes.AddRange([System.Text.Encoding]::Unicode.GetBytes($Template + [char]0))
        while ($bytes.Count % 4) { $bytes.Add(0) }
        $opaque = $(if ($Callback) { $bytes.ToArray() } else { $null })
        [System.Security.AccessControl.CommonAce]::new('None', 'AccessAllowed', $Mask,
            [System.Security.Principal.SecurityIdentifier]::new($Trustee), $Callback, $opaque)
    }
    function New-RestrictionDescriptor([System.Security.AccessControl.GenericAce[]]$Rules)
    {
        $dacl = [System.Security.AccessControl.RawAcl]::new(2, $Rules.Count)
        foreach ($rule in $Rules) { $dacl.InsertAce($dacl.Count, $rule) }
        $identity = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        $security = [System.Security.AccessControl.RawSecurityDescriptor]::new(
            'SelfRelative,DiscretionaryAclPresent', $identity, $identity, $null, $dacl)
        $bytes = [byte[]]::new($security.BinaryLength)
        $security.GetBinaryForm($bytes, 0)
        return ,$bytes
    }
    $good = New-RestrictionDescriptor @(New-RestrictionAce)
    Assert-EnrollmentAgentRestrictions $good $agent $target @('CRAFTUser', '1.2.3')
    Assert-EnrollmentAgentRestrictions (New-RestrictionDescriptor @(New-RestrictionAce -Template '1.2.3')) `
        $agent $target @('CRAFTUser', '1.2.3')
    $unrelated = New-RestrictionAce -Trustee $other -Targets @('S-1-1-0') -Template ''
    Assert-EnrollmentAgentRestrictions (New-RestrictionDescriptor @((New-RestrictionAce), $unrelated)) `
        $agent $target @('CRAFTUser') @($other)
    $invalid = @(
        (New-RestrictionDescriptor @()),
        (New-RestrictionDescriptor @(New-RestrictionAce -Template 'OtherTemplate')),
        (New-RestrictionDescriptor @(New-RestrictionAce -Template '')),
        (New-RestrictionDescriptor @(New-RestrictionAce -Targets @())),
        (New-RestrictionDescriptor @(New-RestrictionAce -Targets @('S-1-1-0'))),
        (New-RestrictionDescriptor @(New-RestrictionAce -Targets @($target, $other))),
        (New-RestrictionDescriptor @(New-RestrictionAce -Mask 1)),
        (New-RestrictionDescriptor @(New-RestrictionAce -Callback $false)),
        (New-RestrictionDescriptor @(New-RestrictionAce -Trustee $other)),
        (New-RestrictionDescriptor @((New-RestrictionAce), $unrelated)),
        (New-RestrictionDescriptor @((New-RestrictionAce),
            (New-RestrictionAce -Trustee 'S-1-5-11' -Template '' -Targets @('S-1-1-0')))),
        [byte[]]@(1, 2, 3)
    )
    $malformed = New-RestrictionAce
    $opaque = $malformed.GetOpaque()
    [BitConverter]::GetBytes([uint32]::MaxValue).CopyTo($opaque, 0)
    $malformed.SetOpaque($opaque)
    $invalid += ,(New-RestrictionDescriptor @($malformed))
    $malformed = New-RestrictionAce
    $opaque = $malformed.GetOpaque()
    $opaque[4] = 2
    $malformed.SetOpaque($opaque)
    $invalid += ,(New-RestrictionDescriptor @($malformed))
    $malformed = New-RestrictionAce
    $opaque = $malformed.GetOpaque()
    $opaque[$opaque.Length - 2] = 1
    $malformed.SetOpaque($opaque)
    $invalid += ,(New-RestrictionDescriptor @($malformed))
    $nullDacl = [System.Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:NO_ACCESS_CONTROL')
    $bytes = [byte[]]::new($nullDacl.BinaryLength)
    $nullDacl.GetBinaryForm($bytes, 0)
    $invalid += ,$bytes
    foreach ($bytes in $invalid)
    {
        $rejected = $false
        try { Assert-EnrollmentAgentRestrictions $bytes $agent $target @('CRAFTUser') }
        catch { $rejected = $true }
        Assert $rejected "Missing, broad or malformed enrollment-agent restrictions were accepted."
    }

    & {
        $history = @()
        $group = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-513')
        $groupBytes = [byte[]]::new($group.BinaryLength)
        $group.GetBinaryForm($groupBytes, 0)
        $tokenGroups = ,$groupBytes
        $mockAdmin = [pscustomobject]@{ Bytes = $good; Fail = $false }
        function Get-ADUser([string]$Identity, [string[]]$Properties, [string]$ErrorAction)
        {
            $agentDn = 'CN=svc-test,CN=Users,DC=example,DC=com'
            if ($Identity -eq $agent -and -not $Properties)
            {
                return [pscustomobject]@{ DistinguishedName = $agentDn }
            }
            if ($Identity -eq $agentDn)
            {
                Assert (($Properties -join '|') -ceq 'tokenGroups|sIDHistory') `
                    "Agent group lookup omitted authorization data."
                return [pscustomobject]@{
                    SID = [System.Security.Principal.SecurityIdentifier]::new($agent)
                    tokenGroups = $tokenGroups
                    sIDHistory = $history
                }
            }
            Assert ($Identity -eq $other) "Policy lookup queried an unexpected account."
            [pscustomobject]@{ SID = [System.Security.Principal.SecurityIdentifier]::new($other) }
        }
        $mockAdmin | Add-Member ScriptMethod GetConfigEntry {
            param($Configuration, $Node, $Entry)
            Assert ($Configuration -eq 'ca.example.com\TestCA' -and $Node -eq '' -and
                $Entry -eq 'EnrollmentAgentRights') "CA policy lookup changed its scope."
            if ($this.Fail) { throw 'Synthetic CA read failure.' }
            return ,$this.Bytes
        }
        function New-Object([string]$ComObject)
        {
            Assert ($ComObject -eq 'CertificateAuthority.Admin') "Unexpected CA policy interface."
            return $mockAdmin
        }
        Assert-CAEnrollmentPolicy 'ca.example.com\TestCA' $agent $target 'CRAFTUser' '1.2.3'
        $mockAdmin.Bytes = New-RestrictionDescriptor @((New-RestrictionAce), $unrelated)
        Assert-CAEnrollmentPolicy 'ca.example.com\TestCA' $agent $target 'CRAFTUser' '1.2.3'
        $history = @([System.Security.Principal.SecurityIdentifier]::new($other))
        $rejected = $false
        try { Assert-CAEnrollmentPolicy 'ca.example.com\TestCA' $agent $target 'CRAFTUser' '1.2.3' }
        catch { $rejected = $true }
        Assert $rejected "Agent SID history bypassed the enrollment restriction check."
        $history = @()
        $tokenGroups = @([System.Security.Principal.SecurityIdentifier]::new($other))
        $rejected = $false
        try { Assert-CAEnrollmentPolicy 'ca.example.com\TestCA' $agent $target 'CRAFTUser' '1.2.3' }
        catch { $rejected = $true }
        Assert $rejected "Agent authorization groups bypassed the enrollment restriction check."
        $mockAdmin.Fail = $true
        $rejected = $false
        try { Assert-CAEnrollmentPolicy 'ca.example.com\TestCA' $agent $target 'CRAFTUser' '1.2.3' }
        catch { $rejected = $_.Exception.Message -like '*Could not verify restrictions*' }
        Assert $rejected "A failed CA policy read was accepted."
    }

    & {
        $events = [System.Collections.Generic.List[string]]::new()
        $policy = New-RestrictionDescriptor @(New-RestrictionAce -Template '')
        $published = @('EnrollmentAgent', 'UnrelatedTemplate')
        $added = [System.Collections.Generic.List[string]]::new()
        $badTemplate = $false
        function Assert-CAEnrollmentPolicy([string]$Configuration, [string]$AgentSid, [string]$TargetSid,
            [string]$Template, [string]$TemplateOid)
        {
            $events.Add('policy')
            Assert-EnrollmentAgentRestrictions $policy $AgentSid $TargetSid @($Template, $TemplateOid)
        }
        function Set-EnrollmentTemplatePermissions([string]$DistinguishedName, [string[]]$AdministratorSids,
            [System.Security.Principal.SecurityIdentifier]$AgentSid,
            [bool]$RemoveAuthenticatedEnroll)
        {
            $events.Add('template-acl')
            Assert ($DistinguishedName -eq 'CN=EnrollmentAgent,offline' -and -not $RemoveAuthenticatedEnroll) `
                "Publication changed an unrelated template."
            if ($badTemplate) { throw 'Synthetic unsafe template ACL.' }
        }
        function Get-ADObject([string]$Identity, [string[]]$Properties)
        {
            $events.Add('read')
            Assert ($Identity -eq 'CN=TestCA,offline') "Publication queried another CA."
            [pscustomobject]@{ certificateTemplates = $published }
        }
        function Set-ADObject([string]$Identity, [hashtable]$Add)
        {
            $events.Add('publish')
            $added.AddRange([string[]]$Add.certificateTemplates)
        }
        $ca = [pscustomobject]@{ DistinguishedName = 'CN=TestCA,offline' }
        $rejected = $false
        try { Publish-CRAFTTemplates $ca 'TestCA' 'CRAFTUser' '1.2.3' $agent $target 'CN=EnrollmentAgent,offline' @() }
        catch { $rejected = $true }
        Assert ($rejected -and ($events -join ',') -eq 'policy') "Publication changed state before verifying CA policy."
        $events.Clear()
        $policy = $good
        $badTemplate = $true
        $rejected = $false
        try { Publish-CRAFTTemplates $ca 'TestCA' 'CRAFTUser' '1.2.3' $agent $target 'CN=EnrollmentAgent,offline' @() }
        catch { $rejected = $true }
        Assert ($rejected -and ($events -join ',') -eq 'policy,template-acl') "Unsafe agent template was published."
        $events.Clear()
        $badTemplate = $false
        Publish-CRAFTTemplates $ca 'TestCA' 'CRAFTUser' '1.2.3' $agent $target 'CN=EnrollmentAgent,offline' @()
        Assert (($events -join ',') -eq 'policy,template-acl,read,publish') "Publication bypassed a policy check."
        Assert ($added.Count -eq 1 -and $added[0] -eq 'CRAFTUser') "Publication changed unrelated or existing templates."
        $events.Clear()
        $published += 'CRAFTUser'
        Publish-CRAFTTemplates $ca 'TestCA' 'CRAFTUser' '1.2.3' $agent $target 'CN=EnrollmentAgent,offline' @()
        Assert (($events -join ',') -eq 'policy,template-acl,read') "Published templates were unnecessarily changed."
    }
}
Write-Host "PASS: scoped CA restrictions, malformed policy rejection and fail-closed publication"

& {
    $agent = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001')
    $administrator = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $users = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-11')
    $enroll = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    function New-TemplateAcl
    {
        $acl = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        $acl.SetOwner($administrator)
        $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $administrator, 'GenericAll', 'Allow'))
        $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new($users, 'GenericRead', 'Allow'))
        return $acl
    }
    $currentAcl = New-TemplateAcl
    Assert-EnrollmentTemplateAcl $currentAcl $agent.Value @($administrator.Value) 'EnrollmentAgent'
    foreach ($case in @(
        @{ Rights = 'ExtendedRight'; ObjectType = $enroll },
        @{ Rights = 'ExtendedRight'; ObjectType = [Guid]::Empty },
        @{ Rights = 'ExtendedRight'; ObjectType = [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2' },
        @{ Rights = 'GenericAll'; ObjectType = [Guid]::Empty },
        @{ Rights = 'WriteProperty'; ObjectType = [Guid]::Empty },
        @{ Rights = 'WriteDacl'; ObjectType = [Guid]::Empty }
    ))
    {
        $acl = New-TemplateAcl
        $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $users, $case.Rights, 'Allow', $case.ObjectType))
        $rejected = $false
        try { Assert-EnrollmentTemplateAcl $acl $agent.Value @($administrator.Value) 'EnrollmentAgent' }
        catch { $rejected = $true }
        Assert $rejected "Unsafe enrollment or template-modification permissions were accepted."
    }
    $acl = New-TemplateAcl
    $acl.SetOwner($users)
    $rejected = $false
    try { Assert-EnrollmentTemplateAcl $acl $agent.Value @($administrator.Value) 'EnrollmentAgent' }
    catch { $rejected = $true }
    Assert $rejected "An untrusted template owner was accepted."
    $acl = New-TemplateAcl
    $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new($agent, 'WriteDacl', 'Allow'))
    $rejected = $false
    try { Assert-EnrollmentTemplateAcl $acl $agent.Value @($administrator.Value) 'EnrollmentAgent' }
    catch { $rejected = $true }
    Assert $rejected "The agent was allowed to change its own template permissions."
    $writes = [System.Collections.Generic.List[object]]::new()
    function Get-Acl([string]$Path)
    {
        Assert ($Path -eq 'AD:offline-template') "ACL test accessed a real template."
        return $currentAcl
    }
    function Set-Acl([string]$Path, $AclObject)
    {
        Assert ($Path -eq 'AD:offline-template') "ACL test wrote an unexpected template."
        $writes.Add($AclObject)
    }
    Set-EnrollmentTemplatePermissions 'offline-template' @($administrator.Value) $agent $false
    $rules = @($currentAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    Assert (@($rules | Where-Object { $_.IdentityReference -eq $agent -and $_.ObjectType -eq $enroll }).Count -eq 1) `
        "The agent was not granted scoped enrollment permission."
    $currentAcl = New-TemplateAcl
    $currentAcl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $users, 'ExtendedRight', 'Allow', $enroll))
    $writes.Clear()
    $rejected = $false
    try { Set-EnrollmentTemplatePermissions 'offline-template' @($administrator.Value) $agent $false }
    catch { $rejected = $true }
    Assert ($rejected -and $writes.Count -eq 0) "Unsafe EnrollmentAgent permissions were silently changed or accepted."
    Set-EnrollmentTemplatePermissions 'offline-template' @($administrator.Value) $agent $true
    Assert ($writes.Count -eq 1) "Explicit Authenticated Users enrollment was not removed from the CRAFT template."
    $currentAcl = New-TemplateAcl
    $inherited = 'O:SYG:SYD:(A;;GA;;;SY)(OA;ID;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;AU)'
    $currentAcl.SetSecurityDescriptorSddlForm($inherited)
    $writes.Clear()
    $rejected = $false
    try { Set-EnrollmentTemplatePermissions 'offline-template' @($administrator.Value) $agent $true }
    catch { $rejected = $true }
    Assert ($rejected -and $writes.Count -eq 0) "Inherited broad enrollment permissions were accepted."
}
Write-Host "PASS: template enrollment/write permissions, owner validation and scoped agent grants"

$topCommands = @($ast.EndBlock.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -in @('Publish-CRAFTTemplates', 'Export-SubmitterKeytab')
}, $false))
Assert ($topCommands.Count -eq 2 -and $topCommands[0].GetCommandName() -eq 'Publish-CRAFTTemplates') `
    "Submitter credentials can be exported before the CA policy check."

$powerShell = (Get-Process -Id $PID).Path
Invoke-CheckedCommand $powerShell @("-NoProfile", "-NonInteractive", "-Command", "exit 0")
Invoke-CheckedCommand $powerShell @("-NoProfile", "-NonInteractive", "-Command",
    "[Console]::Error.WriteLine('SYNTHETIC-NATIVE-WARNING'); exit 0")
$rejected = $false
try
{
    Invoke-CheckedCommand $powerShell @("-NoProfile", "-NonInteractive", "-Command",
        "[Console]::Error.WriteLine('SYNTHETIC-NATIVE-ERROR'); exit 7")
}
catch { $rejected = $_.Exception.Message -like "*exit code 7*" }
Assert $rejected "A failing native command was reported as successful."
$rejected = $false
try { Invoke-CheckedCommand "craft-test-nonexistent-command.exe" @() }
catch { $rejected = $true }
Assert $rejected "A missing native command was reported as successful."
& {
    $root = Join-Path $env:USERPROFILE "CRAFT.Tests.$([Guid]::NewGuid().ToString('N'))"
    Initialize-ExportDirectory $root | Out-Null
    $invalidProgram = Join-Path $root 'invalid-native-program.exe'
    try
    {
        [System.IO.File]::WriteAllText($invalidProgram, 'SYNTHETIC-INVALID-EXECUTABLE')
        $LASTEXITCODE = 0
        $rejected = $false
        try { Invoke-CheckedCommand $invalidProgram @() }
        catch { $rejected = $true }
        Assert $rejected "A native command that failed to start inherited a successful exit status."
    }
    finally
    {
        Remove-Item -LiteralPath $invalidProgram -Force
        Remove-Item -LiteralPath $root -Force
    }
}
Assert ($ErrorActionPreference -eq "Stop") "Native command handling changed the caller's error preference."
Write-Host "PASS: native command success/failure handling"

& {
    $now = Get-Date
    $eku = "1.3.6.1.5.2.3.5"
    $fixtures = @(
        @{ Name = "current"; HasPrivateKey = $true; NotBefore = $now.AddDays(-1); NotAfter = $now.AddDays(1) },
        @{ Name = "expired"; HasPrivateKey = $true; NotBefore = $now.AddDays(-2); NotAfter = $now.AddDays(-1) },
        @{ Name = "future"; HasPrivateKey = $true; NotBefore = $now.AddDays(1); NotAfter = $now.AddDays(2) },
        @{ Name = "no-key"; HasPrivateKey = $false; NotBefore = $now.AddDays(-1); NotAfter = $now.AddDays(1) },
        @{ Name = "wrong-eku"; HasPrivateKey = $true; NotBefore = $now.AddDays(-1); NotAfter = $now.AddDays(1) }
    ) | ForEach-Object {
        $_.EnhancedKeyUsageList = @([pscustomobject]@{
            ObjectId = $(if ($_.Name -eq "wrong-eku") { "1.2.3" } else { $eku })
        })
        $_.DnsNameList = @([pscustomobject]@{ Unicode = "dc.example.com" })
        [pscustomobject]$_
    }
    function Get-ChildItem([string]$LiteralPath)
    {
        Assert ($LiteralPath -eq "offline-cert-store") "Certificate test attempted to access a real store."
        $fixtures
    }
    $selected = @(Get-UsableCertificate "offline-cert-store" $eku "dc.example.com")
    Assert ($selected.Count -eq 1 -and $selected[0].Name -eq "current") "Certificate selection accepted an unusable key."
    $wrongHost = @(Get-UsableCertificate "offline-cert-store" $eku "other.example.com")
    Assert ($wrongHost.Count -eq 0) "Certificate selection accepted a different DC's identity."
}
Write-Host "PASS: certificate validity, private key and EKU selection"
Write-Host "All offline provisioning checks passed; no AD, CA, account or certificate-store changes were made."
