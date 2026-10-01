# Offline checks only: extract pure helpers without executing provisioning commands.
$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "Configure-CRAFT-CA.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors.Message -join "`n") }

foreach ($name in @("Invoke-CheckedCommand", "Get-UsableCertificate", "Initialize-ExportDirectory",
    "New-AccountPassword", "Initialize-CRAFTAccount", "Export-SubmitterKeytab"))
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
            '/pass', '+rndpass', '/minpass', '64', '/maxpass', '64', '/answer', '+',
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

$powerShell = (Get-Process -Id $PID).Path
Invoke-CheckedCommand $powerShell @("-NoProfile", "-NonInteractive", "-Command", "exit 0")
$rejected = $false
try { Invoke-CheckedCommand $powerShell @("-NoProfile", "-NonInteractive", "-Command", "exit 7") }
catch { $rejected = $_.Exception.Message -like "*exit code 7*" }
Assert $rejected "A failing native command was reported as successful."
$rejected = $false
try { Invoke-CheckedCommand "craft-test-nonexistent-command.exe" @() }
catch { $rejected = $true }
Assert $rejected "A missing native command was reported as successful."
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
