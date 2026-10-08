# Offline enrollment/export checks; only newly created synthetic certificates are used.
#requires -Version 5.0
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'Request-CRAFT-Certificate.cmd'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors.Message -join "`n") }
foreach ($definition in $ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $false))
{
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Assert([bool]$Condition, [string]$Message)
{
    if (-not $Condition) { throw $Message }
}

function Reject([scriptblock]$Action)
{
    $rejected = $false
    try { & $Action | Out-Null }
    catch { $rejected = $true }
    Assert $rejected 'An invalid or conflicting export was accepted.'
}

function Read-Pem([string]$Path, [string]$Label)
{
    $text = [System.IO.File]::ReadAllText($Path)
    Assert ($text.StartsWith("-----BEGIN $Label-----`n") -and
        $text.EndsWith("-----END $Label-----`n") -and -not $text.Contains("`r")) 'Unexpected PEM framing.'
    return ,([Convert]::FromBase64String(($text -replace '-----[^\n]+-----', '').Trim()))
}

function Invoke-Cmd([string]$Command)
{
    $start = [System.Diagnostics.ProcessStartInfo]::new($env:ComSpec, '/d /s /c ' + $Command)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($start)
    try
    {
        $output = $process.StandardOutput.ReadToEnd() + $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        return [pscustomobject]@{ Output = $output; ExitCode = $process.ExitCode }
    }
    finally { $process.Dispose() }
}

function Get-Certificate
{
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Template, [uri]$Url, [string]$CertStoreLocation)
    $script:requests++
    Assert ($Template -eq 'OfflineUserLogon' -and $Url.OriginalString -eq 'ldap:' -and
        $CertStoreLocation -eq 'Cert:\CurrentUser\My') 'Incorrect enrollment policy or user store.'
    if ($script:status -ne 'Issued') { return [pscustomobject]@{ Status = $script:status; Certificate = $null } }
    return [pscustomobject]@{ Status = 'Issued'; Certificate = Get-Item -LiteralPath $script:certificatePath }
}

function New-CraftFixture([double]$Days, [string]$Profile = 'Valid')
{
    $extensions = @('2.5.29.19={critical}{text}ca=0', '2.5.29.37={text}1.3.6.1.4.1.311.20.2.2',
        '2.5.29.17={text}upn=offline@example.invalid')
    $parameters = @{
        KeyAlgorithm = 'RSA'; KeyLength = 2048; KeyExportPolicy = 'Exportable'
        Provider = 'Microsoft Software Key Storage Provider'; Type = 'Custom'; KeyUsage = 'DigitalSignature'
        Subject = ('CN=CRAFT OFFLINE TEST ' + [Guid]::NewGuid()); CertStoreLocation = 'Cert:\CurrentUser\My'
        NotBefore = (Get-Date).AddMinutes(-1); NotAfter = (Get-Date).AddDays($Days)
    }
    switch ($Profile)
    {
        'Future' { $parameters.NotBefore = (Get-Date).AddDays(1) }
        'Expired' { $parameters.NotBefore = (Get-Date).AddDays(-3); $parameters.NotAfter = (Get-Date).AddDays(-1) }
        'MissingBC' { $extensions = @($extensions | Where-Object { $_ -notlike '2.5.29.19=*' }) }
        'CA' { $extensions[0] = '2.5.29.19={critical}{text}ca=1' }
        'MissingUPN' { $extensions = @($extensions | Where-Object { $_ -notlike '2.5.29.17=*' }) }
        'DuplicateUPN' { $extensions[2] = '2.5.29.17={text}upn=one@example.invalid&upn=two@example.invalid' }
        'WrongEKU' { $extensions[1] = '2.5.29.37={text}1.3.6.1.5.5.7.3.2' }
        'SigningCA' { $parameters.KeyUsage = @('DigitalSignature', 'CertSign') }
        'NoSignature' { $parameters.KeyUsage = 'KeyEncipherment' }
        'PKINIT' { $extensions[1] = '2.5.29.37={text}1.3.6.1.5.2.3.4' }
    }
    $parameters.TextExtension = $extensions
    $certificate = New-SelfSignedCertificate @parameters
    $path = 'Cert:\CurrentUser\My\' + $certificate.Thumbprint
    $fixtures.Add($path)
    $certificate.Dispose()
    return $path
}

function Set-CraftFixtureProfile($Request)
{
    $basic = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
        $false, $false, 0, $true)
    $Request.CertificateExtensions.Add($basic)
    $Request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $usages = [System.Security.Cryptography.OidCollection]::new()
    [void]$usages.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.4.1.311.20.2.2'))
    $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($usages, $false)
    $Request.CertificateExtensions.Add($eku)
    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddUserPrincipalName('offline@example.invalid')
    $Request.CertificateExtensions.Add($san.Build())
}

function Read-CraftSnapshot($Target)
{
    foreach ($name in @('user.pem', 'user.key', '.craft-certificate.json'))
    {
        (Get-FileHash -LiteralPath (Join-Path $Target.Path $name) -Algorithm SHA256).Hash
    }
}

$root = Join-Path $env:USERPROFILE ('CRAFT.Certificate.Tests.' + [Guid]::NewGuid().ToString('N'))
$fixtures = [System.Collections.Generic.List[string]]::new()
$script:requests = 0
$script:status = 'Issued'
try
{
    $template = "Preview & O'Brien [x] (1)!"
    $preview = Join-Path $root $template
    $command = '""' + $scriptPath + '" "' + $template + '" "' + $preview +
        '" /DeleteAfterExport /RenewBeforeDays 2 /WhatIf"'
    $result = Invoke-Cmd $command
    Assert ($result.ExitCode -eq 0 -and $result.Output.Contains($template) -and
        $result.Output.Contains($preview) -and $result.Output.Contains('less than 2 day(s)') -and
        $result.Output.Contains('remove the Windows certificate')) ('CMD preview failed: ' + $result.Output)
    Assert (-not (Test-Path -LiteralPath $root)) 'CMD preview changed the filesystem.'
    $command = '""' + $scriptPath + '" "' + $template + '" "' + $preview + '" /WhatIf"'
    $result = Invoke-Cmd $command
    Assert ($result.ExitCode -eq 0 -and $result.Output.Contains('one calendar month') -and
        -not (Test-Path -LiteralPath $root)) 'The default CMD renewal window is not one calendar month.'
    $command = "& ([scriptblock]::Create([IO.File]::ReadAllText('" + $scriptPath.Replace("'", "''") +
        "'))) -TemplateName '" + $template.Replace("'", "''") + "' -Destination '" +
        $preview.Replace("'", "''") + "' -DeleteAfterExport -RenewBeforeDays 2 -WhatIf"
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
    $output = & powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1
    Assert ($LASTEXITCODE -eq 0 -and ($output -join "`n").Contains($template) -and
        ($output -join "`n").Contains($preview) -and ($output -join "`n").Contains('less than 2 day(s)') -and
        ($output -join "`n").Contains('remove the Windows certificate')) 'PowerShell preview lost its arguments.'
    Assert (-not (Test-Path -LiteralPath $root)) 'PowerShell preview changed the filesystem.'
    $command = "& '" + $scriptPath.Replace("'", "''") + "' '" + $template.Replace("'", "''") +
        "' '" + $preview.Replace("'", "''") + "' /RenewBeforeDays 2 /WhatIf /DeleteAfterExport"
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
    $output = & powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1
    Assert ($LASTEXITCODE -eq 0 -and ($output -join "`n").Contains($template) -and
        ($output -join "`n").Contains($preview) -and ($output -join "`n").Contains('less than 2 day(s)') -and
        ($output -join "`n").Contains('remove the Windows certificate')) 'PowerShell CMD launch lost its arguments.'
    Assert (-not (Test-Path -LiteralPath $root)) 'PowerShell CMD preview changed the filesystem.'
    $command = '""' + $scriptPath + '""'
    $result = Invoke-Cmd $command
    Assert ($result.ExitCode -eq 64) 'Missing CMD arguments did not return the usage status.'
    Write-Host 'PASS: CMD and Windows PowerShell previews preserve arguments without enrollment or files'

    Initialize-CraftKeyExporter
    $target = Initialize-CraftCertificateDestination $root
    $algorithms = @(
        @{ Name = 'CNG-RSA'; KeyAlgorithm = 'RSA'; KeyLength = 2048;
            Provider = 'Microsoft Software Key Storage Provider' },
        @{ Name = 'Encrypted-export-only'; KeyAlgorithm = 'RSA'; KeyLength = 2048;
            Provider = 'Microsoft Software Key Storage Provider' },
        @{ Name = 'CSP-RSA'; KeyAlgorithm = 'RSA'; KeyLength = 2048;
            Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'; KeySpec = 'Signature' },
        @{ Name = 'CNG-ECDSA'; KeyAlgorithm = 'ECDSA_nistP256';
            Provider = 'Microsoft Software Key Storage Provider' }
    )
    foreach ($algorithm in $algorithms)
    {
        $parameters = $algorithm.Clone()
        $name = $parameters.Name
        $parameters.Remove('Name')
        $sourceKey = $null
        $sourceRsa = $null
        if ($name -eq 'Encrypted-export-only')
        {
            $creation = [System.Security.Cryptography.CngKeyCreationParameters]::new()
            $creation.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowExport
            $creation.Parameters.Add([System.Security.Cryptography.CngProperty]::new('Length',
                [BitConverter]::GetBytes(2048), [System.Security.Cryptography.CngPropertyOptions]::None))
            $sourceKey = [System.Security.Cryptography.CngKey]::Create(
                [System.Security.Cryptography.CngAlgorithm]::Rsa, ('CRAFT.TEST.' + [Guid]::NewGuid()), $creation)
            $sourceRsa = [System.Security.Cryptography.RSACng]::new($sourceKey)
            try
            {
                $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    ('CN=CRAFT OFFLINE TEST ' + [Guid]::NewGuid()), $sourceRsa,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                Set-CraftFixtureProfile $request
                $certificate = $request.CreateSelfSigned([DateTimeOffset]::Now.AddMinutes(-1),
                    [DateTimeOffset]::Now.AddMinutes(15))
                $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
                try { $store.Open('ReadWrite'); $store.Add($certificate) }
                finally { $store.Dispose() }
            }
            catch { $sourceKey.Delete(); throw }
            finally { $sourceRsa.Dispose(); $sourceKey.Dispose() }
        }
        else
        {
            $certificate = New-SelfSignedCertificate @parameters -Type Custom -KeyExportPolicy Exportable `
                -CertStoreLocation 'Cert:\CurrentUser\My' -Subject ('CN=CRAFT OFFLINE TEST ' + [Guid]::NewGuid()) `
                -KeyUsage DigitalSignature -NotAfter (Get-Date).AddMinutes(15) `
                -TextExtension @('2.5.29.19={critical}{text}ca=0', '2.5.29.37={text}1.3.6.1.4.1.311.20.2.2', `
                    '2.5.29.17={text}upn=offline@example.invalid')
        }
        $script:certificatePath = 'Cert:\CurrentUser\My\' + $certificate.Thumbprint
        $fixtures.Add($script:certificatePath)
        if ($name -eq 'Encrypted-export-only')
        {
            $sourceKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey(
                $certificate)
            try
            {
                Reject { $sourceKey.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob) }
            }
            finally { $sourceKey.Dispose() }
        }
        $export = Initialize-CraftCertificateDestination (Join-Path $root $name)
        Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' | Out-Null
        $certificateBytes = Read-Pem (Join-Path $export.Path 'user.pem') 'CERTIFICATE'
        $keyBytes = Read-Pem (Join-Path $export.Path 'user.key') 'PRIVATE KEY'
        $published = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateBytes)
        $key = [System.Security.Cryptography.CngKey]::Import($keyBytes,
            [System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        $private = $null
        $public = $null
        try
        {
            Assert ($published.Thumbprint -eq $certificate.Thumbprint) 'Export selected a different certificate.'
            $message = [System.Text.Encoding]::UTF8.GetBytes('SYNTHETIC OFFLINE SIGNATURE CHECK')
            if ($name -eq 'CNG-ECDSA')
            {
                $private = [System.Security.Cryptography.ECDsaCng]::new($key)
                $public = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey(
                    $published)
                $signature = $private.SignData($message, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
                Assert ($public.VerifyData($message, $signature,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256)) 'ECDSA PEM pair does not match.'
            }
            else
            {
                $private = [System.Security.Cryptography.RSACng]::new($key)
                $public = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
                    $published)
                $signature = $private.SignData($message, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                Assert ($public.VerifyData($message, $signature,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)) 'RSA PEM pair does not match.'
            }
            $allowed = @([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
                'S-1-5-18', 'S-1-5-32-544')
            foreach ($file in @('user.pem', 'user.key'))
            {
                $acl = Get-Acl -LiteralPath (Join-Path $export.Path $file)
                Assert $acl.AreAccessRulesProtected 'Export inherited destination permissions.'
                foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
                {
                    Assert ($rule.IdentityReference.Value -in $allowed) 'An ordinary user can access the export.'
                }
            }
            Assert (@(Get-ChildItem -LiteralPath $export.Path -Filter '*.pfx').Count -eq 0) 'PFX was saved to disk.'
            $before = $script:requests
            Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -RenewBeforeDays 0 | Out-Null
            Assert ($script:requests -eq $before) 'Existing output triggered another certificate request.'
            Assert (Test-Path -LiteralPath $script:certificatePath) 'Default export deleted the Windows certificate.'
            Assert ([Convert]::ToBase64String((Read-Pem (Join-Path $export.Path 'user.key') 'PRIVATE KEY')) -eq
                [Convert]::ToBase64String($keyBytes)) 'Existing private key was changed.'
            $openssl = Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'
            if (Test-Path -LiteralPath $openssl)
            {
                & $openssl pkey -in (Join-Path $export.Path 'user.key') -check -noout
                Assert ($LASTEXITCODE -eq 0) 'OpenSSL rejected the PKCS#8 PEM key.'
                & $openssl x509 -in (Join-Path $export.Path 'user.pem') -noout
                Assert ($LASTEXITCODE -eq 0) 'OpenSSL rejected the certificate PEM.'
            }
            Write-Host "PASS: $name matching PEM export, private ACLs, and existing-output preservation"
        }
        finally
        {
            if ($null -ne $public) { $public.Dispose() }
            if ($null -ne $private) { $private.Dispose() }
            $key.Dispose()
            $published.Dispose()
            [Array]::Clear($keyBytes, 0, $keyBytes.Length)
        }
        $original = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey(
            (Get-Item -LiteralPath $script:certificatePath))
        if ($null -ne $original) { $original.SignData($message,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) | Out-Null; $original.Dispose() }
        $certificate.Dispose()
    }

    $script:certificatePath = $fixtures[0]
    $export = Initialize-CraftCertificateDestination (Join-Path $root 'PublicationConflict')
    $script:competingKey = Join-Path $export.Path 'user.key'
    $script:pemWriter = ${function:Write-CraftPem}
    function Write-CraftPem([string]$Path, [string]$Label, [byte[]]$Bytes,
        [System.Security.AccessControl.FileSecurity]$Security)
    {
        & $script:pemWriter $Path $Label $Bytes $Security
        if ($Label -eq 'PRIVATE KEY')
        {
            [System.IO.File]::WriteAllText($script:competingKey, 'Competing output to preserve.')
        }
    }
    try
    {
        Reject { Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' }
        Assert (-not (Test-Path -LiteralPath (Join-Path $export.Path 'user.pem')) -and
            [System.IO.File]::ReadAllText($script:competingKey) -eq 'Competing output to preserve.') `
            'Partial publication changed another output or left an incomplete certificate pair.'
        Assert (@(Get-ChildItem -LiteralPath $export.Path -Directory).Count -eq 0) 'Staged private key was retained.'
        Assert (Test-Path -LiteralPath $script:certificatePath) 'Publication failure removed the Windows credential.'
    }
    finally { Set-Item -LiteralPath Function:\Write-CraftPem -Value $script:pemWriter }
    Write-Host 'PASS: publication conflicts preserve competing files and remove only staged/published files'

    $certificate = New-SelfSignedCertificate -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable `
        -Type Custom -Subject ('CN=CRAFT NONEXPORTABLE TEST ' + [Guid]::NewGuid()) `
        -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddMinutes(15) `
        -TextExtension @('2.5.29.19={critical}{text}ca=0', '2.5.29.37={text}1.3.6.1.4.1.311.20.2.2', `
            '2.5.29.17={text}upn=offline@example.invalid')
    $script:certificatePath = 'Cert:\CurrentUser\My\' + $certificate.Thumbprint
    $nonexportablePath = $script:certificatePath
    $fixtures.Add($script:certificatePath)
    $export = Initialize-CraftCertificateDestination (Join-Path $root 'Nonexportable')
    try
    {
        Reject { Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' }
        Assert (@(Get-ChildItem -LiteralPath $export.Path -Filter 'user.*').Count -eq 0) `
            'Nonexportable key published files.'
    }
    finally { $certificate.Dispose() }
    Write-Host 'PASS: nonexportable keys fail without publishing files'

    foreach ($value in @('Pending', 'Denied'))
    {
        $script:status = $value
        $export = Initialize-CraftCertificateDestination (Join-Path $root $value)
        $code = $null
        $rejected = $false
        try { Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' }
        catch { $rejected = $true; $code = $_.Exception.Data['CraftExitCode'] }
        Assert $rejected 'Pending or denied request unexpectedly succeeded.'
        if ($value -eq 'Pending') { Assert ($code -eq 2) 'Pending approval did not return its distinct status.' }
        Assert (-not (Test-Path -LiteralPath (Join-Path $export.Path 'user.pem')) -and
            -not (Test-Path -LiteralPath (Join-Path $export.Path 'user.key'))) 'A failed request published files.'
    }
    Write-Host 'PASS: pending and denied requests publish no PEM files'

    $script:status = 'Issued'
    $script:certificatePath = New-CraftFixture 60
    $reusePath = $script:certificatePath
    $export = Initialize-CraftCertificateDestination (Join-Path $root 'ReuseAndDelete')
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' | Out-Null
    $snapshot = (Read-CraftSnapshot $export) -join ':'
    $before = $script:requests
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' | Out-Null
    Assert ($script:requests -eq $before -and (Test-Path -LiteralPath $reusePath) -and
        ((Read-CraftSnapshot $export) -join ':') -eq $snapshot) 'A current pair was renewed or deleted by default.'
    $powerShell7 = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    if ($powerShell7)
    {
        $command = "& '" + $scriptPath.Replace("'", "''") + "' OfflineUserLogon '" +
            $export.Path.Replace("'", "''") + "'; exit " + '$LASTEXITCODE'
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
        $output = & $powerShell7.Source -NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded 2>&1
        Assert ($LASTEXITCODE -eq 0 -and ($output -join "`n").Contains('Reusing certificate')) `
            'A real CMD launch from PowerShell 7 could not load the Windows PowerShell modules.'
        Assert (((Read-CraftSnapshot $export) -join ':') -eq $snapshot) 'PowerShell 7 reuse changed the export.'
        Write-Host 'PASS: PowerShell 7 CMD launch loads ACL/enrollment modules and reuses output offline'
    }
    $stored = Get-Item -LiteralPath $reusePath
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($stored)
    $keyName = $rsa.Key.KeyName
    $provider = $rsa.Key.Provider
    $rsa.Dispose()
    $stored.Dispose()
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -DeleteAfterExport | Out-Null
    Assert ($script:requests -eq $before -and -not (Test-Path -LiteralPath $reusePath) -and
        ((Read-CraftSnapshot $export) -join ':') -eq $snapshot) 'Optional deletion changed the exported pair.'
    Reject { $key = [System.Security.Cryptography.CngKey]::Open($keyName, $provider); $key.Dispose() }
    Write-Host 'PASS: current pairs are reused and Windows certificate/key deletion defaults off'

    $script:certificatePath = New-CraftFixture 3
    $deletePath = $script:certificatePath
    $export = Initialize-CraftCertificateDestination (Join-Path $root 'DeleteAfterNewExport')
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -DeleteAfterExport | Out-Null
    Assert (-not (Test-Path -LiteralPath $deletePath) -and
        (Test-Path -LiteralPath (Join-Path $export.Path 'user.pem')) -and
        (Test-Path -LiteralPath (Join-Path $export.Path 'user.key'))) 'Fresh export deletion removed the PEM pair.'
    Write-Host 'PASS: optional deletion runs after a successful fresh export'

    $script:certificatePath = New-CraftFixture 5
    $sharedPath = $script:certificatePath
    $stored = Get-Item -LiteralPath $sharedPath
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($stored)
    $sibling = $null
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
    try
    {
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            ('CN=CRAFT OFFLINE TEST SHARED ' + [Guid]::NewGuid()), $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $sibling = $request.CreateSelfSigned([DateTimeOffset]::Now.AddMinutes(-1), [DateTimeOffset]::Now.AddDays(5))
        $store.Open('ReadWrite')
        $store.Add($sibling)
        $siblingPath = 'Cert:\CurrentUser\My\' + $sibling.Thumbprint
        $fixtures.Add($siblingPath)
    }
    finally
    {
        $store.Dispose()
        if ($null -ne $sibling) { $sibling.Dispose() }
        $rsa.Dispose()
        $stored.Dispose()
    }
    $export = Initialize-CraftCertificateDestination (Join-Path $root 'SharedKey')
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -DeleteAfterExport | Out-Null
    Assert (-not (Test-Path -LiteralPath $sharedPath) -and (Test-Path -LiteralPath $siblingPath)) `
        'Deletion removed another Windows certificate.'
    $stored = Get-Item -LiteralPath $siblingPath
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($stored)
    try
    {
        Assert ($null -ne $rsa) 'Deletion removed a shared private key.'
        $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes('SHARED KEY CHECK'),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) | Out-Null
    }
    finally { if ($null -ne $rsa) { $rsa.Dispose() }; $stored.Dispose() }
    Write-Host 'PASS: deletion preserves other Windows certificates and their shared private keys'

    $container = 'CRAFT.TEST.CSP.' + [Guid]::NewGuid().ToString('N')
    $dualPaths = @()
    $containerNames = @()
    foreach ($spec in @(2, 1))
    {
        $parameters = [System.Security.Cryptography.CspParameters]::new(24,
            'Microsoft Enhanced RSA and AES Cryptographic Provider', $container)
        $parameters.KeyNumber = $spec
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048, $parameters)
        $certificate = $null
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
        try
        {
            $containerNames += $rsa.CspKeyContainerInfo.UniqueKeyContainerName
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                ('CN=CRAFT OFFLINE TEST DUAL CSP ' + $spec + ' ' + [Guid]::NewGuid()), $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            Set-CraftFixtureProfile $request
            $certificate = $request.CreateSelfSigned([DateTimeOffset]::Now.AddMinutes(-1),
                [DateTimeOffset]::Now.AddDays(60))
            $store.Open('ReadWrite')
            $store.Add($certificate)
            $path = 'Cert:\CurrentUser\My\' + $certificate.Thumbprint
            $fixtures.Add($path)
            $dualPaths += $path
        }
        finally
        {
            $store.Dispose()
            if ($null -ne $certificate) { $certificate.Dispose() }
            $rsa.Dispose()
        }
    }
    $first = Get-Item -LiteralPath $dualPaths[0]
    $second = Get-Item -LiteralPath $dualPaths[1]
    try
    {
        Assert ($containerNames[0] -eq $containerNames[1] -and
            $first.GetPublicKeyString() -ne $second.GetPublicKeyString()) 'Invalid dual-key CSP fixture.'
    }
    finally { $first.Dispose(); $second.Dispose() }
    $script:certificatePath = $dualPaths[0]
    $export = Initialize-CraftCertificateDestination (Join-Path $root 'DualCspKeys')
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -DeleteAfterExport | Out-Null
    Assert (-not (Test-Path -LiteralPath $dualPaths[0]) -and (Test-Path -LiteralPath $dualPaths[1])) `
        'Deleting the signing certificate removed the exchange certificate.'
    $second = Get-Item -LiteralPath $dualPaths[1]
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($second)
    try
    {
        $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes('DUAL CSP EXCHANGE KEY CHECK'),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) | Out-Null
    }
    finally { $rsa.Dispose(); $second.Dispose() }
    Write-Host 'PASS: distinct CSP signing/exchange keys in one container survive certificate deletion'

    $script:certificatePath = New-CraftFixture 20
    $oldPath = $script:certificatePath
    $export = Initialize-CraftCertificateDestination (Join-Path $root 'ValidateBeforeReplace')
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' | Out-Null
    $snapshot = (Read-CraftSnapshot $export) -join ':'
    foreach ($profile in @('Future', 'Expired', 'MissingBC', 'CA', 'MissingUPN', 'DuplicateUPN',
        'WrongEKU', 'SigningCA', 'NoSignature'))
    {
        $script:certificatePath = New-CraftFixture 60 $profile
        Reject { Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -DeleteAfterExport }
        Assert ((Test-Path -LiteralPath $oldPath) -and (Test-Path -LiteralPath $script:certificatePath) -and
            ((Read-CraftSnapshot $export) -join ':') -eq $snapshot -and
            -not (Test-Path -LiteralPath (Join-Path $export.Path '.craft-certificate.transaction.json'))) `
            "Invalid $profile replacement changed the working pair or removed a Windows credential."
    }
    $script:certificatePath = New-CraftFixture 60 'PKINIT'
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' | Out-Null
    Write-Host 'PASS: replacement dates, CA constraints, usages and one UPN are checked before publication/deletion'

    $script:certificatePath = New-CraftFixture 20
    $oldPath = $script:certificatePath
    $export = Initialize-CraftCertificateDestination (Join-Path $root 'RetryStoreCleanup')
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' | Out-Null
    $script:certificatePath = New-CraftFixture 60
    $newPath = $script:certificatePath
    $script:failCleanupThumbprint = Split-Path -Leaf $oldPath
    $script:remover = (Get-Item -LiteralPath Function:\Remove-CraftStoredCertificate).ScriptBlock
    function Remove-CraftStoredCertificate([string]$Thumbprint)
    {
        if ($Thumbprint -eq $script:failCleanupThumbprint) { throw 'Synthetic store cleanup failure.' }
        & $script:remover $Thumbprint
    }
    try
    {
        Reject { Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -DeleteAfterExport }
        $state = [IO.File]::ReadAllText((Join-Path $export.Path '.craft-certificate.json')) | ConvertFrom-Json
        Assert ((Split-Path -Leaf $oldPath) -in $state.PendingCleanup -and
            (Split-Path -Leaf $newPath) -in $state.PendingCleanup -and
            (Test-Path -LiteralPath $oldPath) -and (Test-Path -LiteralPath $newPath)) `
            'Failed store cleanup lost its pending deletion requests.'
    }
    finally { Set-Item -LiteralPath Function:\Remove-CraftStoredCertificate -Value $script:remover }
    $before = $script:requests
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' | Out-Null
    $state = [IO.File]::ReadAllText((Join-Path $export.Path '.craft-certificate.json')) | ConvertFrom-Json
    Assert ($script:requests -eq $before -and -not (Test-Path -LiteralPath $oldPath) -and
        -not (Test-Path -LiteralPath $newPath) -and @($state.PendingCleanup).Count -eq 0) `
        'A retry did not finish pending old/current cleanup without issuing another certificate.'
    Write-Host 'PASS: failed store cleanup persists and retries both requested deletions on the next run'

    $oldCrashPath = New-CraftFixture 20
    $newCrashPath = New-CraftFixture 60
    foreach ($checkpoint in @('Preparing', 'Ready', 'user.pem', 'user.key', '.craft-certificate.json'))
    {
        $script:certificatePath = $oldCrashPath
        $export = Initialize-CraftCertificateDestination (Join-Path $root ('Crash.' + $checkpoint))
        Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' | Out-Null
        $snapshot = (Read-CraftSnapshot $export) -join ':'
        $child = @'
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$tokens=$null
$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile('%%SCRIPT%%',[ref]$tokens,[ref]$errors)
foreach ($definition in $ast.FindAll({param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
},$false)) { . ([scriptblock]::Create($definition.Extent.Text)) }
function Get-Certificate
{
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Template,[uri]$Url,[string]$CertStoreLocation)
    return [pscustomobject]@{Status='Issued';Certificate=Get-Item -LiteralPath '%%CERTIFICATE%%'}
}
$source=(Get-Item -LiteralPath Function:\Publish-CraftCertificateExport).ScriptBlock.ToString()
$source='function Publish-CraftCertificateExport {'+$source+'}'
$checkpoint='%%CHECKPOINT%%'
if ($checkpoint -in @('Preparing','Ready'))
{
    $needle="Save-CraftExportJson `$Target '.craft-certificate.transaction.json' `$journal"
    $index=if ($checkpoint -eq 'Preparing') {$source.IndexOf($needle)} else {$source.LastIndexOf($needle)}
    if ($index -lt 0) {throw 'Missing transaction crash checkpoint.'}
    $source=$source.Insert($index+$needle.Length,'; [Environment]::Exit(73)')
}
else
{
    $needle='else { [System.IO.File]::Move((Join-Path $stage $name), $path) }'
    $crash="; if (`$name -eq '$checkpoint') { [Environment]::Exit(73) }"
    if (-not $source.Contains($needle)) {throw 'Missing publication crash checkpoint.'}
    $source=$source.Replace($needle,$needle+$crash)
}
. ([scriptblock]::Create($source))
Initialize-CraftKeyExporter
$target=Initialize-CraftCertificateDestination '%%DESTINATION%%'
Invoke-CraftCertificateEnrollment $target 'OfflineUserLogon'
'@
        $child = $child.Replace('%%SCRIPT%%', $scriptPath.Replace("'", "''"))
        $child = $child.Replace('%%CERTIFICATE%%', $newCrashPath.Replace("'", "''"))
        $child = $child.Replace('%%DESTINATION%%', $export.Path.Replace("'", "''"))
        $child = $child.Replace('%%CHECKPOINT%%', $checkpoint)
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($child))
        $executable = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $command = '""' + $executable + '" -NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $encoded + '"'
        $result = Invoke-Cmd $command
        Assert ($result.ExitCode -eq 73) ("The $checkpoint crash was not reached: " + $result.Output)
        Assert (Test-Path -LiteralPath (Join-Path $export.Path '.craft-certificate.transaction.json')) `
            'A killed exporter left no durable recovery journal.'
        $before = $script:requests
        $script:certificatePath = $newCrashPath
        Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -RenewBeforeDays 0 | Out-Null
        Assert ($script:requests -eq $before -and
            -not (Test-Path -LiteralPath (Join-Path $export.Path '.craft-certificate.transaction.json')) -and
            @(Get-ChildItem -LiteralPath $export.Path -Directory).Count -eq 0) 'Recovery was not complete and offline.'
        if ($checkpoint -eq '.craft-certificate.json')
        {
            $state = [IO.File]::ReadAllText((Join-Path $export.Path '.craft-certificate.json')) | ConvertFrom-Json
            Assert ($state.Thumbprint -eq (Split-Path -Leaf $newCrashPath) -and
                -not (Test-Path -LiteralPath $oldCrashPath) -and (Test-Path -LiteralPath $newCrashPath)) `
                'Recovery rolled back a committed generation or lost its pending cleanup.'
        }
        else
        {
            Assert (((Read-CraftSnapshot $export) -join ':') -eq $snapshot -and
                (Test-Path -LiteralPath $oldCrashPath)) 'Recovery did not restore the complete old generation.'
        }
    }
    Write-Host 'PASS: killed exporters recover preparation, ready state and every publication checkpoint'

    $script:certificatePath = New-CraftFixture 20
    $oldPath = $script:certificatePath
    $export = Initialize-CraftCertificateDestination (Join-Path $root 'Renew')
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' | Out-Null
    $snapshot = (Read-CraftSnapshot $export) -join ':'
    foreach ($value in @('Pending', 'Denied'))
    {
        $script:status = $value
        Reject { Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -DeleteAfterExport }
        Assert ((Test-Path -LiteralPath $oldPath) -and
            ((Read-CraftSnapshot $export) -join ':') -eq $snapshot) 'Failed renewal removed the working credential.'
    }
    $script:status = 'Issued'
    $script:certificatePath = $nonexportablePath
    Reject { Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -DeleteAfterExport }
    Assert ((Test-Path -LiteralPath $oldPath) -and
        ((Read-CraftSnapshot $export) -join ':') -eq $snapshot) 'Failed key export changed the working pair.'
    $script:certificatePath = New-CraftFixture 45
    $newPath = $script:certificatePath
    $busy = [System.IO.File]::Open((Join-Path $export.Path 'user.key'), [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try { Reject { Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -DeleteAfterExport } }
    finally { $busy.Dispose() }
    Assert ((Test-Path -LiteralPath $oldPath) -and (Test-Path -LiteralPath $newPath) -and
        ((Read-CraftSnapshot $export) -join ':') -eq $snapshot -and
        @(Get-ChildItem -LiteralPath $export.Path -Directory).Count -eq 0) 'Publication failure did not restore output.'
    $before = $script:requests
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' | Out-Null
    $pem = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Read-Pem (Join-Path $export.Path 'user.pem') 'CERTIFICATE'))
    try
    {
        Assert ($script:requests -eq $before + 1 -and -not (Test-Path -LiteralPath $oldPath) -and
            (Test-Path -LiteralPath $newPath) -and $pem.Thumbprint -eq (Split-Path -Leaf $newPath)) `
            'Default renewal did not replace the pair and remove the old Windows certificate.'
    }
    finally { $pem.Dispose() }
    $script:certificatePath = New-CraftFixture 90
    $nextPath = $script:certificatePath
    Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' -RenewBeforeDays 60 -DeleteAfterExport | Out-Null
    Assert (-not (Test-Path -LiteralPath $newPath) -and -not (Test-Path -LiteralPath $nextPath)) `
        'Custom renewal/deletion did not remove both managed Windows certificates.'
    $before = $script:requests
    Reject { Invoke-CraftCertificateEnrollment $export 'DifferentTemplate' }
    [System.IO.File]::WriteAllText((Join-Path $export.Path 'user.key'), 'Changed file to preserve.')
    Reject { Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' }
    Assert ($script:requests -eq $before -and
        [System.IO.File]::ReadAllText((Join-Path $export.Path 'user.key')) -eq 'Changed file to preserve.') `
        'Changed output or a different template triggered enrollment or overwriting.'
    Write-Host 'PASS: one-month/custom renewal, rollback, old-certificate deletion, and changed-file protection'

    $export = Initialize-CraftCertificateDestination (Join-Path $root 'Busy')
    $busy = [System.IO.File]::Open((Join-Path $export.Path '.craft-certificate-export.lock'),
        [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try
    {
        $before = $script:requests
        Reject { Invoke-CraftCertificateEnrollment $export 'OfflineUserLogon' }
        Assert ($script:requests -eq $before) 'A concurrent export submitted another request.'
    }
    finally { $busy.Dispose() }
    $junction = Join-Path $root 'Redirect'
    New-Item -ItemType Junction -Path $junction -Target $export.Path | Out-Null
    try { Reject { Initialize-CraftCertificateDestination (Join-Path $junction 'Nested') } }
    finally { [System.IO.Directory]::Delete($junction) }
    Write-Host 'PASS: concurrent export and redirected destination refusal'
}
finally
{
    foreach ($path in $fixtures)
    {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -DeleteKey -Force }
    }
    $fullPath = [System.IO.Path]::GetFullPath($root)
    if ([System.IO.Path]::GetDirectoryName($fullPath) -ne $env:USERPROFILE -or
        [System.IO.Path]::GetFileName($fullPath) -notlike 'CRAFT.Certificate.Tests.*')
    {
        throw 'Unexpected certificate test cleanup path.'
    }
    if (Test-Path -LiteralPath $fullPath) { Remove-Item -LiteralPath $fullPath -Recurse -Force }
}
Write-Host 'Offline enrollment/export checks passed. No AD CA was contacted.'
