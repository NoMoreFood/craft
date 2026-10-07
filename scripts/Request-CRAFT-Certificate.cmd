<# ::
@ECHO OFF
SETLOCAL DisableDelayedExpansion
IF "%~1"=="" GOTO Usage
IF "%~2"=="" GOTO Usage
SET CRAFT_CERTIFICATE_SCRIPT="%~f0"
SET CRAFT_CERTIFICATE_TEMPLATE="%~1"
SET CRAFT_CERTIFICATE_DESTINATION="%~2"
SET CRAFT_CERTIFICATE_WHATIF=0
SET CRAFT_CERTIFICATE_DELETE=0
SET CRAFT_CERTIFICATE_RENEW_DAYS=
SHIFT /1
SHIFT /1
:Options
IF "%~1"=="" GOTO Run
IF /I "%~1"=="/WhatIf" GOTO Preview
IF /I "%~1"=="/DeleteAfterExport" GOTO DeleteAfterExport
IF /I "%~1"=="/RenewBeforeDays" GOTO RenewBeforeDays
GOTO Usage
:Preview
SET CRAFT_CERTIFICATE_WHATIF=1
SHIFT /1
GOTO Options
:DeleteAfterExport
SET CRAFT_CERTIFICATE_DELETE=1
SHIFT /1
GOTO Options
:RenewBeforeDays
IF "%~2"=="" GOTO Usage
SET CRAFT_CERTIFICATE_RENEW_DAYS="%~2"
SHIFT /1
SHIFT /1
GOTO Options
:Run
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" ^
    -NoLogo -NoProfile -NonInteractive -Command ^
    "$craftOptions = @{TemplateName=$env:CRAFT_CERTIFICATE_TEMPLATE.Trim([char]34);" ^
    "Destination=$env:CRAFT_CERTIFICATE_DESTINATION.Trim([char]34);" ^
    "DeleteAfterExport=($env:CRAFT_CERTIFICATE_DELETE -eq '1');" ^
    "WhatIf=($env:CRAFT_CERTIFICATE_WHATIF -eq '1')};" ^
    "if ($env:CRAFT_CERTIFICATE_RENEW_DAYS) {" ^
    "$craftOptions.RenewBeforeDays=$env:CRAFT_CERTIFICATE_RENEW_DAYS.Trim([char]34)};" ^
    "& ([scriptblock]::Create([IO.File]::ReadAllText($env:CRAFT_CERTIFICATE_SCRIPT.Trim([char]34)))) @craftOptions"
EXIT /B %ERRORLEVEL%
:Usage
ECHO Usage: %~nx0 template-name destination-directory ^
    [/RenewBeforeDays days] [/DeleteAfterExport] [/WhatIf]
EXIT /B 64
#>
#requires -Version 5.0
<#
.SYNOPSIS
    Requests a user certificate and exports CRAFT's PEM certificate and private key.

.DESCRIPTION
    Windows Active Directory enrollment policy selects an eligible CA for the template.
    Enrollment uses the signed-in user's credentials and Cert:\CurrentUser\My without elevation.
    The template must permit user enrollment and exportable RSA or ECDSA software keys.
    Select a logon template compatible with CRAFT's home-certificate requirements and KDC mapping.

    The destination is a local Windows directory. The script creates private export files
    user.pem and user.key, reuses a pair until less than one calendar month remains, then replaces it.
    Successful replacement removes the old Windows certificate. DeleteAfterExport defaults off
    and optionally removes the current Windows certificate after successful export or reuse.
    The key is unencrypted PKCS#8 PEM; no OpenSSL installation or on-disk PFX is required.
    Pending requests remain in the Windows request store and produce no PEM pair.

.PARAMETER TemplateName
    Certificate template internal name or OID; no CA name is needed.

.PARAMETER Destination
    Local Windows directory for user.pem, user.key and the helper's private tracking metadata.

.PARAMETER RenewBeforeDays
    Override the default one-calendar-month window with this many days, including fractional days.
    Set 0 to replace only expired certificates. Run again to check; there is no background scheduler.

.PARAMETER DeleteAfterExport
    Remove the current Windows certificate after successful export or reuse. Default: off.
    The private key is deleted only when no other Windows-store certificate shares it.
    Exported PEM files remain available for Linux. Failed/pending exports retain Windows credentials.

.EXAMPLE
    .\Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate"
    Run from CMD or PowerShell as the authorized user.

.EXAMPLE
    .\Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate" /WhatIf
    Preview without enrollment or filesystem changes.

.EXAMPLE
    .\Request-CRAFT-Certificate.cmd UserLogon "C:\Users\Alice\CRAFT Certificate" /DeleteAfterExport
    Ensure a current PEM pair and remove its Windows-store certificate after success.

.NOTES
    Windows PowerShell 5.x, .NET Framework 4.6 or newer, and the Windows PKI module are required.
    Transfer the pair to the Linux user's ~/.config/craft and set user.key permissions to 0600.
    Linux trust anchors/CRLs and KDC mapping must accept the issuing CA and certificate.
    Exit codes: 0 success/preview, 1 failure, 2 pending approval, 64 CMD usage error.
    Enrollment reference: https://learn.microsoft.com/powershell/module/pki/get-certificate
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[^\x00-\x1f\x7f"]{1,256}$')]
    [string]$TemplateName,
    [Parameter(Mandatory, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]$Destination,
    [ValidateRange(0, 3650)]
    [Nullable[decimal]]$RenewBeforeDays = $null,
    [switch]$DeleteAfterExport
)

$ErrorActionPreference = 'Stop'

function Initialize-CraftKeyExporter
{
    if ('Craft.CertificateKeyExporter' -as [type]) { return }

    # Use an in-memory PFX roundtrip to support exportable CNG keys that disallow direct plaintext export.
    Add-Type -TypeDefinition @'
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Craft
{
    public static class CertificateKeyExporter
    {
        private static byte[] ExportCng(CngKey key)
        {
            // Permit plaintext export on the temporary imported key without changing the Windows-store key.
            int policy = (int)(CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport);
            key.SetProperty(new CngProperty("Export Policy", BitConverter.GetBytes(policy), CngPropertyOptions.None));
            return key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
        }

        public static byte[] Export(X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey)
                throw new InvalidOperationException("The issued certificate has no accessible private key.");

            byte[] pfx = null;
            byte[] random = new byte[32];
            try
            {
                // Encrypt the temporary PKCS#12 representation entirely in memory.
                using (RandomNumberGenerator generator = RandomNumberGenerator.Create())
                    generator.GetBytes(random);
                string password = Convert.ToBase64String(random);
                pfx = certificate.Export(X509ContentType.Pkcs12, password);
                X509KeyStorageFlags flags = X509KeyStorageFlags.Exportable;
                flags |= Enum.IsDefined(typeof(X509KeyStorageFlags), "EphemeralKeySet")
                    ? (X509KeyStorageFlags)32 : X509KeyStorageFlags.UserKeySet;

                using (X509Certificate2 copy = new X509Certificate2(pfx, password, flags))
                using (RSA rsa = RSACertificateExtensions.GetRSAPrivateKey(copy))
                {
                    // Export CNG keys directly and convert legacy CSP RSA keys using the native CNG encoder.
                    if (rsa is RSACng)
                        return ExportCng(((RSACng)rsa).Key);
                    if (rsa != null)
                    {
                        RSAParameters parameters = rsa.ExportParameters(true);
                        try
                        {
                            using (RSACng converted = new RSACng())
                            {
                                converted.ImportParameters(parameters);
                                return ExportCng(converted.Key);
                            }
                        }
                        finally
                        {
                            foreach (byte[] value in new byte[][] {
                                parameters.D, parameters.P, parameters.Q,
                                parameters.DP, parameters.DQ, parameters.InverseQ })
                                if (value != null) Array.Clear(value, 0, value.Length);
                        }
                    }

                    // Windows ECDSA certificates use CNG's PKCS#8 encoder.
                    using (ECDsa ecdsa = ECDsaCertificateExtensions.GetECDsaPrivateKey(copy))
                    {
                        if (ecdsa is ECDsaCng)
                            return ExportCng(((ECDsaCng)ecdsa).Key);
                    }
                    throw new InvalidOperationException("Use an exportable RSA or ECDSA software-key template.");
                }
            }
            finally
            {
                Array.Clear(random, 0, random.Length);
                if (pfx != null) Array.Clear(pfx, 0, pfx.Length);
            }
        }
    }
}
'@
}

function Initialize-CraftCertificateDestination([string]$Directory)
{
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Directory).TrimEnd('\')
    if ($path -notmatch '^[A-Za-z]:\\' -or $path.Length -le 3)
    {
        throw 'Destination must be a dedicated local Windows directory, not a drive root or UNC path.'
    }
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $caller = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $allowed = @($caller.Value, 'S-1-5-18', 'S-1-5-32-544')
    $trusted = $allowed + 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    $unsafeRights = [int][System.Security.AccessControl.FileSystemRights]('WriteData,WriteAttributes,' +
        'WriteExtendedAttributes,DeleteSubdirectoriesAndFiles,Delete,ChangePermissions,TakeOwnership') -bor 0x50000000
    $missing = [System.Collections.Generic.List[string]]::new()

    # Reject redirected paths and parents another ordinary user can replace.
    for ($parent = [System.IO.DirectoryInfo]::new($path); $null -ne $parent; $parent = $parent.Parent)
    {
        if (-not (Test-Path -LiteralPath $parent.FullName)) { $missing.Add($parent.FullName); continue }
        $item = Get-Item -LiteralPath $parent.FullName -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint))
        {
            throw 'Destination and its parents must be ordinary directories, without junctions or symlinks.'
        }
        $acl = Get-Acl -LiteralPath $parent.FullName
        if ($acl.GetOwner($sidType).Value -notin $trusted) { throw 'Destination has an untrusted directory owner.' }
        foreach ($rule in $acl.GetAccessRules($true, $true, $sidType))
        {
            if ($rule.AccessControlType -eq 'Allow' -and
                -not ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -and
                $rule.IdentityReference.Value -notin $trusted -and ([int]$rule.FileSystemRights -band $unsafeRights))
            {
                throw 'Destination has a parent writable or replaceable by another user.'
            }
        }
    }

    # Apply private permissions at creation without changing unrelated existing directories or files.
    $directoryAcl = [System.Security.AccessControl.DirectorySecurity]::new()
    $fileAcl = [System.Security.AccessControl.FileSecurity]::new()
    $directoryAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.SetAccessRuleProtection($true, $false)
    foreach ($sid in $allowed | Select-Object -Unique)
    {
        $identity = $sidType::new($sid)
        $directoryAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        $fileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', 'Allow'))
    }
    $missing.Reverse()
    foreach ($name in $missing)
    {
        [System.IO.Directory]::CreateDirectory($name, $directoryAcl) | Out-Null
        $item = Get-Item -LiteralPath $name -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
            (Get-Acl -LiteralPath $name).GetOwner($sidType).Value -notin $allowed)
        {
            throw 'Destination changed while creating its directories.'
        }
    }
    return [pscustomobject]@{ Path = $path; DirectoryAcl = $directoryAcl; FileAcl = $fileAcl }
}

function Write-CraftExportFile([string]$Path, [string]$Content,
    [System.Security.AccessControl.FileSecurity]$Security)
{
    # Create a private file before writing certificate, key or tracking data.
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::CreateNew,
        [System.Security.AccessControl.FileSystemRights]::Write, [System.IO.FileShare]::None,
        4096, [System.IO.FileOptions]::None, $Security)
    $writer = $null
    try
    {
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
        $writer.Write($Content)
        $writer.Flush()
        $stream.Flush($true)
    }
    finally
    {
        if ($null -ne $writer) { $writer.Dispose() }
        $stream.Dispose()
    }
}

function Write-CraftPem([string]$Path, [string]$Label, [byte[]]$Bytes,
    [System.Security.AccessControl.FileSecurity]$Security)
{
    $content = [System.Text.StringBuilder]::new()
    [void]$content.Append("-----BEGIN $Label-----`n")
    $encoded = [Convert]::ToBase64String($Bytes)
    for ($offset = 0; $offset -lt $encoded.Length; $offset += 64)
    {
        [void]$content.Append($encoded.Substring($offset, [Math]::Min(64, $encoded.Length - $offset))).Append("`n")
    }
    [void]$content.Append("-----END $Label-----`n")
    Write-CraftExportFile $Path $content.ToString() $Security
}

function Remove-CraftStoredCertificate([string]$Thumbprint)
{
    $path = 'Cert:\CurrentUser\My\' + $Thumbprint
    if (-not (Test-Path -LiteralPath $path)) { return }
    $certificate = Get-Item -LiteralPath $path
    $others = @()
    $shared = $false
    try
    {
        # Preserve keys shared by another certificate in the current user's store.
        $others = @(Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My')
        foreach ($other in $others)
        {
            if ($other.Thumbprint -ne $Thumbprint -and
                $other.PublicKey.Oid.Value -eq $certificate.PublicKey.Oid.Value -and
                $other.GetPublicKeyString() -eq $certificate.GetPublicKeyString())
            {
                $shared = $true
                break
            }
        }
        Remove-Item -LiteralPath $path -DeleteKey:(-not $shared) -Force -Confirm:$false -ErrorAction Stop
        Write-Host "Removed Windows certificate: $path"
    }
    finally
    {
        foreach ($other in $others) { $other.Dispose() }
        $certificate.Dispose()
    }
}

function Invoke-CraftCertificateEnrollment($Target, [string]$Template,
    [Nullable[decimal]]$RenewBeforeDays = $null, [switch]$DeleteAfterExport)
{
    $certificatePath = Join-Path $Target.Path 'user.pem'
    $keyPath = Join-Path $Target.Path 'user.key'
    $statePath = Join-Path $Target.Path '.craft-certificate.json'
    $names = @('user.pem', 'user.key', '.craft-certificate.json')
    $lockPath = Join-Path $Target.Path '.craft-certificate-export.lock'
    $lock = $null
    $certificate = $null
    $previous = $null
    $privateKey = $null
    $stage = $null
    $published = [System.Collections.Generic.List[string]]::new()
    $backups = [System.Collections.Generic.List[string]]::new()
    $success = $false
    try
    {
        # Serialize callers before requesting a certificate or publishing the two files.
        if (Test-Path -LiteralPath $lockPath)
        {
            $item = Get-Item -LiteralPath $lockPath -Force
            if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint))
            {
                throw 'The export lock must be an ordinary file.'
            }
        }
        $lock = [System.IO.FileStream]::new($lockPath, [System.IO.FileMode]::OpenOrCreate,
            [System.Security.AccessControl.FileSystemRights]('Read,Write'), [System.IO.FileShare]::None,
            4096, [System.IO.FileOptions]::None, $Target.FileAcl)

        # Reuse only a complete, unchanged pair recorded for this template by the helper.
        $existing = @($names | Where-Object { Test-Path -LiteralPath (Join-Path $Target.Path $_) })
        if ($existing.Count -and $existing.Count -ne $names.Count)
        {
            throw 'Destination contains incomplete or unmanaged output. Choose a new destination.'
        }
        if ($existing.Count)
        {
            $sidType = [System.Security.Principal.SecurityIdentifier]
            $allowed = @([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
                'S-1-5-18', 'S-1-5-32-544')
            foreach ($name in $names)
            {
                $path = Join-Path $Target.Path $name
                $item = Get-Item -LiteralPath $path -Force
                $acl = Get-Acl -LiteralPath $path
                if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
                    $item.Length -lt 1 -or $item.Length -gt 1MB -or $acl.GetOwner($sidType).Value -notin $allowed)
                {
                    throw 'Managed export files must be private, ordinary files owned by the caller.'
                }
                foreach ($rule in $acl.GetAccessRules($true, $true, $sidType))
                {
                    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed)
                    {
                        throw 'Managed export files permit access by another user.'
                    }
                }
            }
            $state = [System.IO.File]::ReadAllText($statePath) | ConvertFrom-Json
            if ($state.TemplateName -ne $Template -or $state.Thumbprint -notmatch '^[0-9A-F]{40}$' -or
                $state.CertificateHash -ne (Get-FileHash -LiteralPath $certificatePath -Algorithm SHA256).Hash -or
                $state.PrivateKeyHash -ne (Get-FileHash -LiteralPath $keyPath -Algorithm SHA256).Hash)
            {
                throw 'Managed output was changed or belongs to a different template. Choose a new destination.'
            }
            $pem = [System.IO.File]::ReadAllText($certificatePath)
            if ($pem -notmatch '\A-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)' +
                '-----END CERTIFICATE-----\r?\n\z')
            {
                throw 'Managed certificate PEM is invalid.'
            }
            $previous = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                [Convert]::FromBase64String($Matches[1]))
            if ($previous.Thumbprint -ne $state.Thumbprint -or $previous.NotBefore.ToUniversalTime() -gt
                [DateTime]::UtcNow)
            {
                throw 'Managed certificate identity or validity is invalid.'
            }
            $expiration = $previous.NotAfter.ToUniversalTime()
            $renewalStart = if ($null -eq $RenewBeforeDays) { $expiration.AddMonths(-1) }
                else { $expiration.AddDays(-[double]$RenewBeforeDays) }
            if ([DateTime]::UtcNow -le $renewalStart)
            {
                Write-Host "Reusing certificate valid until $($previous.NotAfter.ToUniversalTime().ToString('u'))."
                if ($DeleteAfterExport) { Remove-CraftStoredCertificate $previous.Thumbprint }
                Write-Output $certificatePath
                Write-Output $keyPath
                return
            }
            $window = if ($null -eq $RenewBeforeDays) { 'one calendar month' } else { "$RenewBeforeDays day(s)" }
            Write-Host "Certificate renewal is due within $window of expiration."
        }

        # Let Windows AD enrollment policy choose an eligible enterprise CA for the requesting user.
        Write-Host "Requesting template '$Template' as the signed-in user..."
        $result = Get-Certificate -Template $Template -Url 'ldap:' -CertStoreLocation 'Cert:\CurrentUser\My' `
            -Confirm:$false -ErrorAction Stop
        if ([string]$result.Status -eq 'Pending')
        {
            $error = [System.InvalidOperationException]::new(
                'Certificate approval is pending in the Windows request store; no PEM files were written.')
            $error.Data['CraftExitCode'] = 2
            throw $error
        }
        if ([string]$result.Status -ne 'Issued' -or $null -eq $result.Certificate)
        {
            throw "Certificate was not issued (status: $($result.Status))."
        }
        $certificate = $result.Certificate
        if ($certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow -or
            ($null -ne $previous -and $certificate.Thumbprint -eq $previous.Thumbprint))
        {
            throw 'Enrollment did not return a current replacement certificate.'
        }
        try { $privateKey = [Craft.CertificateKeyExporter]::Export($certificate) }
        catch { throw 'The private key cannot be exported. Use a template permitting exportable software keys.' }

        # Stage the complete pair and its tracking data before replacing managed output.
        $stage = Join-Path $Target.Path ('.craft-certificate.' + [Guid]::NewGuid().ToString('N'))
        [System.IO.Directory]::CreateDirectory($stage, $Target.DirectoryAcl) | Out-Null
        Write-CraftPem (Join-Path $stage 'user.pem') 'CERTIFICATE' $certificate.RawData $Target.FileAcl
        Write-CraftPem (Join-Path $stage 'user.key') 'PRIVATE KEY' $privateKey $Target.FileAcl
        $state = [ordered]@{
            TemplateName = $Template
            Thumbprint = $certificate.Thumbprint
            CertificateHash = (Get-FileHash -LiteralPath (Join-Path $stage 'user.pem') -Algorithm SHA256).Hash
            PrivateKeyHash = (Get-FileHash -LiteralPath (Join-Path $stage 'user.key') -Algorithm SHA256).Hash
        } | ConvertTo-Json -Compress
        Write-CraftExportFile (Join-Path $stage '.craft-certificate.json') $state $Target.FileAcl
        foreach ($name in $existing)
        {
            [System.IO.File]::Move((Join-Path $Target.Path $name), (Join-Path $stage ('old-' + $name)))
            $backups.Add($name)
        }
        foreach ($name in $names)
        {
            $path = Join-Path $Target.Path $name
            [System.IO.File]::Move((Join-Path $stage $name), $path)
            $published.Add($path)
        }
        $success = $true
        Write-Host "Issued by: $($certificate.Issuer)"
        Write-Host "Windows certificate: Cert:\CurrentUser\My\$($certificate.Thumbprint)"
        if ($null -ne $previous) { Remove-CraftStoredCertificate $previous.Thumbprint }
        if ($DeleteAfterExport) { Remove-CraftStoredCertificate $certificate.Thumbprint }
        Write-Output $certificatePath
        Write-Output $keyPath
    }
    finally
    {
        # Restore the previous pair on publication failure; retain credentials on enrollment/export failure.
        if ($null -ne $privateKey) { [Array]::Clear($privateKey, 0, $privateKey.Length) }
        if ($null -ne $certificate) { $certificate.Dispose() }
        if ($null -ne $previous) { $previous.Dispose() }
        try
        {
            if (-not $success)
            {
                foreach ($path in $published) { [System.IO.File]::Delete($path) }
                foreach ($name in $backups)
                {
                    [System.IO.File]::Move((Join-Path $stage ('old-' + $name)), (Join-Path $Target.Path $name))
                }
            }
            if ($null -ne $stage -and [System.IO.Directory]::Exists($stage))
            {
                foreach ($name in $names) { [System.IO.File]::Delete((Join-Path $stage $name)) }
                if ($success)
                {
                    foreach ($name in $backups) { [System.IO.File]::Delete((Join-Path $stage ('old-' + $name))) }
                }
                [System.IO.Directory]::Delete($stage, $false)
            }
        }
        catch { Write-Warning "Could not restore or clean export files in '$($Target.Path)'; secure and inspect them." }
        finally { if ($null -ne $lock) { $lock.Dispose() } }
    }
}

try
{
    # Resolve local prerequisites before issuing a request; a preview makes no external or filesystem changes.
    Get-Command Get-Certificate -ErrorAction Stop | Out-Null
    $window = if ($null -eq $RenewBeforeDays) { 'one calendar month' } else { "$RenewBeforeDays day(s)" }
    $action = "Ensure template '$TemplateName' PEM pair; renew with less than $window remaining"
    if ($DeleteAfterExport) { $action += '; remove the Windows certificate after export' }
    if (-not $PSCmdlet.ShouldProcess($Destination, $action))
    {
        return
    }
    Initialize-CraftKeyExporter
    $target = Initialize-CraftCertificateDestination $Destination
    Invoke-CraftCertificateEnrollment $target $TemplateName $RenewBeforeDays -DeleteAfterExport:$DeleteAfterExport
}
catch
{
    [Console]::Error.WriteLine('Request-CRAFT-Certificate: ' + $_.Exception.Message)
    $code = $_.Exception.Data['CraftExitCode']
    if ($null -eq $code) { $code = 1 }
    exit $code
}
