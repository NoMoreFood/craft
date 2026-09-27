# Offline checks only: extract pure helpers without executing provisioning commands.
$ErrorActionPreference = "Stop"
$scriptPath = Join-Path $PSScriptRoot "Configure-CRAFT-CA.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors.Message -join "`n") }

foreach ($name in @("Invoke-CheckedCommand", "Get-UsableCertificate"))
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

$parameterCheck = [scriptblock]::Create($ast.ParamBlock.Extent.Text + "`n" +
    '[pscustomobject]@{ ValidityHours = $ValidityHours; KeySize = $KeySize; CesUrl = $CesUrl }')
$valid = @{ AllowedTargetGroup = "CRAFT Test Users"; ExportPassword = "offline-test-only";
    CesUrl = "https://ces.example.com/service.svc/CES" }
$defaults = & $parameterCheck @valid
Assert ($defaults.ValidityHours -eq 10 -and $defaults.KeySize -eq 3072) "Unexpected certificate defaults."
foreach ($case in @(
    @{ ValidityHours = 0 }, @{ ValidityHours = 25 }, @{ KeySize = 2048 }, @{ KeySize = 4096 },
    @{ TemplateName = "Invalid,Name" }, @{ EnrollmentAgentIdentity = "bad'user" },
    @{ TargetUser = "bad(user)" }, @{ EnrollmentAgentName = 'bad"name' },
    @{ CesUrl = "http://ces.example.com/" }, @{ CesUrl = "/relative" },
    @{ CesUrl = "https://user@ces.example.com/" }, @{ CesUrl = "https://ces.example.com/#fragment" },
    @{ AllowedTargetGroup = "" }, @{ ExportPassword = "" }
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
