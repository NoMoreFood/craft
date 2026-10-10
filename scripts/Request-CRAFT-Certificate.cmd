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
SET PSModulePath=%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" ^
    -NoLogo -NoProfile -NonInteractive -Command ^
    "if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {" ^
    "Write-Warning 'This host runs unsigned PowerShell in Constrained Language Mode. Sign a .ps1 copy of this file and run that copy; see its help notes.';" ^
    "exit 1 };" ^
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
    Certificate dates, CA constraints, signing/logon usage and exactly one UPN SAN are checked before publication.
    Interrupted publication recovers on the next invocation, and failed store cleanup remains queued for retry.
    Pending CA requests remain in the Windows request store and retain existing exports.

.PARAMETER TemplateName
    Certificate template internal name or OID; no CA name is needed.

.PARAMETER Destination
    Local Windows directory for user.pem, user.key and the helper's private tracking metadata.

.PARAMETER RenewBeforeDays
    Override the default one-calendar-month window with this many days, including fractional days.
    Set 0 to replace only expired certificates. Run again to check; there is no background scheduler.

.PARAMETER DeleteAfterExport
    Remove the current Windows certificate after successful export or reuse. Default: off.
    The private key is deleted only when provider/container metadata proves it is not shared by another
    current-user certificate. Unknown or shared key containers are retained without prompting for a PIN.
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
    The CMD wrapper uses built-in Windows PowerShell modules even when invoked from PowerShell 7.
    The wrapper runs this file as an unsigned in-memory script. Where AppLocker or WDAC script rules put
    such scripts in Constrained Language Mode it stops with a warning: copy the file to
    Request-CRAFT-Certificate.ps1, sign that copy with a trusted code-signing certificate, and run it with
    -TemplateName, -Destination, -RenewBeforeDays, -DeleteAfterExport and -WhatIf.
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
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Craft
{
    public static class CertificateKeyExporter
    {
        [DllImport("crypt32.dll", SetLastError = true)]
        private static extern bool CertGetCertificateContextProperty(
            IntPtr context, uint property, IntPtr data, ref uint size);

        [StructLayout(LayoutKind.Sequential)]
        private struct KeyProviderInfo
        {
            public IntPtr Container, Provider;
            public uint Type, Flags, Count;
            public IntPtr Parameters;
            public uint Spec;
        }

        public static string KeyContainer(X509Certificate2 certificate)
        {
            // Read provider metadata without opening private keys or prompting for a hardware-key PIN.
            uint size = 0;
            if (!CertGetCertificateContextProperty(certificate.Handle, 2, IntPtr.Zero, ref size) ||
                size < Marshal.SizeOf(typeof(KeyProviderInfo))) return null;
            IntPtr buffer = Marshal.AllocHGlobal(checked((int)size));
            try
            {
                if (!CertGetCertificateContextProperty(certificate.Handle, 2, buffer, ref size)) return null;
                KeyProviderInfo info = (KeyProviderInfo)Marshal.PtrToStructure(buffer, typeof(KeyProviderInfo));
                string container = Marshal.PtrToStringUni(info.Container);
                string provider = Marshal.PtrToStringUni(info.Provider);
                if (String.IsNullOrEmpty(container) || String.IsNullOrEmpty(provider)) return null;

                // Signing and exchange keys in a CSP share the container; KeySpec must not distinguish them.
                return info.Type + "\0" + (info.Flags & 0x20) + "\0" + provider + "\0" + container;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private struct DerNode
        {
            public int Tag, Start, End;
        }

        private static DerNode ReadDer(byte[] data, ref int cursor, int end)
        {
            // Decode bounded DER nodes, rejecting indefinite, overflowing or truncated lengths.
            if (cursor + 2 > end) throw new InvalidOperationException("Invalid certificate SAN encoding.");
            int tag = data[cursor++], length = data[cursor++];
            if ((length & 0x80) != 0)
            {
                int count = length & 0x7f;
                if (count == 0 || count > 4 || cursor + count > end || data[cursor] == 0)
                    throw new InvalidOperationException("Invalid certificate SAN length.");
                length = 0;
                for (int i = 0; i < count; ++i) length = checked(length * 256 + data[cursor++]);
                if (length < 128) throw new InvalidOperationException("Non-DER certificate SAN length.");
            }
            if (length > end - cursor) throw new InvalidOperationException("Truncated certificate SAN.");
            DerNode node = new DerNode { Tag = tag, Start = cursor, End = cursor + length };
            cursor = node.End;
            return node;
        }

        private static X509Extension FindExtension(X509Certificate2 certificate, string oid, bool required)
        {
            X509Extension result = null;
            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension.Oid.Value != oid) continue;
                if (result != null) throw new InvalidOperationException("Duplicate certificate extension: " + oid);
                result = extension;
            }
            if (result == null && required)
                throw new InvalidOperationException("Missing certificate extension: " + oid);
            return result;
        }

        public static void ValidateProfile(X509Certificate2 certificate, bool current)
        {
            // Match CRAFT's leaf policy before accepting an export; Linux separately checks trust and CRLs.
            if (current && (certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
                certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow.AddSeconds(60)))
                throw new InvalidOperationException("Certificate must be currently valid for at least 60 seconds.");

            // An end-entity certificate may omit basicConstraints, as stock AD CS templates do; one that is
            // present must not describe a CA. The key-usage check below rules out certificate signing.
            X509Extension constraints = FindExtension(certificate, "2.5.29.19", false);
            X509BasicConstraintsExtension basic = constraints == null
                ? null : new X509BasicConstraintsExtension(constraints, false);
            X509KeyUsageExtension usage = new X509KeyUsageExtension(
                FindExtension(certificate, "2.5.29.15", true), false);
            X509EnhancedKeyUsageExtension eku = new X509EnhancedKeyUsageExtension(
                FindExtension(certificate, "2.5.29.37", true), false);
            if ((basic != null && (basic.CertificateAuthority || basic.HasPathLengthConstraint)) ||
                (usage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0 ||
                (usage.KeyUsages & (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)) != 0 ||
                !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.4.1.311.20.2.2" ||
                    oid.Value == "1.3.6.1.5.2.3.4"))
                throw new InvalidOperationException("Use a non-CA digital-signature logon certificate.");

            // Require exactly one UTF8String Microsoft UPN otherName, including valid nested DER framing.
            byte[] san = FindExtension(certificate, "2.5.29.17", true).RawData;
            byte[] upnOid = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03 };
            int cursor = 0, count = 0;
            DerNode names = ReadDer(san, ref cursor, san.Length);
            if (names.Tag != 0x30 || cursor != san.Length)
                throw new InvalidOperationException("Invalid certificate SAN sequence.");
            cursor = names.Start;
            while (cursor < names.End)
            {
                DerNode name = ReadDer(san, ref cursor, names.End);
                if (name.Tag != 0xa0) continue;
                int inner = name.Start;
                DerNode oid = ReadDer(san, ref inner, name.End);
                DerNode value = ReadDer(san, ref inner, name.End);
                if (oid.Tag != 6 || value.Tag != 0xa0 || inner != name.End)
                    throw new InvalidOperationException("Invalid certificate otherName.");
                if (!san.Skip(oid.Start).Take(oid.End - oid.Start).SequenceEqual(upnOid)) continue;
                inner = value.Start;
                DerNode text = ReadDer(san, ref inner, value.End);
                if (text.Tag != 0x0c || inner != value.End)
                    throw new InvalidOperationException("Certificate UPN must be UTF8String.");
                new UTF8Encoding(false, true).GetString(san, text.Start, text.End - text.Start);
                ++count;
            }
            if (count != 1) throw new InvalidOperationException("Certificate needs exactly one UPN otherName.");
        }

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

function Assert-CraftPrivatePath([string]$Path, [switch]$Directory, [switch]$AllowEmpty)
{
    $item = Get-Item -LiteralPath $Path -Force
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $allowed = @([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path
    if ($item.PSIsContainer -ne [bool]$Directory -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
        $acl.GetOwner($sidType).Value -notin $allowed -or
        (-not $Directory -and ($item.Length -gt 1MB -or (-not $AllowEmpty -and $item.Length -lt 1))))
    {
        throw 'Export paths must be private, ordinary files/directories owned by the caller.'
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, $sidType))
    {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed)
        {
            throw 'Export paths permit access by another user.'
        }
    }
}

function Get-CraftExportHash([string]$Path)
{
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    Assert-CraftPrivatePath $Path -AllowEmpty
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Save-CraftExportJson($Target, [string]$Name, $Value)
{
    # Flush the complete private document before atomically replacing its fixed name.
    $path = Join-Path $Target.Path $Name
    $temporary = Join-Path $Target.Path ('.craft-certificate.json.' + [Guid]::NewGuid().ToString('N'))
    try
    {
        Write-CraftExportFile $temporary ($Value | ConvertTo-Json -Depth 8 -Compress) $Target.FileAcl
        if (Test-Path -LiteralPath $path)
        {
            Assert-CraftPrivatePath $path
            [System.IO.File]::Replace($temporary, $path, [System.Management.Automation.Language.NullString]::Value)
        }
        else { [System.IO.File]::Move($temporary, $path) }
    }
    finally { [System.IO.File]::Delete($temporary) }
}

function Read-CraftExportState($Target, [string]$Template)
{
    $names = @('user.pem', 'user.key', '.craft-certificate.json')
    $hashes = [ordered]@{}
    foreach ($name in $names) { $hashes[$name] = Get-CraftExportHash (Join-Path $Target.Path $name) }
    $existing = @($hashes.Values | Where-Object { $null -ne $_ })
    if (-not $existing.Count) { return $null }
    if ($existing.Count -ne $names.Count)
    {
        throw 'Destination contains incomplete or unmanaged output. Choose a new destination.'
    }
    $state = [System.IO.File]::ReadAllText((Join-Path $Target.Path '.craft-certificate.json')) | ConvertFrom-Json
    if ($state -isnot [pscustomobject] -or $state.TemplateName -ne $Template -or
        $state.Thumbprint -notmatch '^[0-9A-F]{40}$' -or $state.CertificateHash -ne $hashes['user.pem'] -or
        $state.PrivateKeyHash -ne $hashes['user.key'])
    {
        throw 'Managed output was changed or belongs to a different template. Choose a new destination.'
    }
    if (-not $state.PSObject.Properties['PendingCleanup'])
    {
        $state | Add-Member -NotePropertyName PendingCleanup -NotePropertyValue @()
    }
    $state.PendingCleanup = @($state.PendingCleanup | Select-Object -Unique)
    if ($state.PendingCleanup.Count -gt 32 -or
        @($state.PendingCleanup | Where-Object { $_ -isnot [string] -or $_ -notmatch '^[0-9A-F]{40}$' }).Count)
    {
        throw 'Invalid certificate cleanup tracking data.'
    }
    $pem = [System.IO.File]::ReadAllText((Join-Path $Target.Path 'user.pem'))
    if ($pem -notmatch '\A-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)' +
        '-----END CERTIFICATE-----\r?\n\z')
    {
        throw 'Managed certificate PEM is invalid.'
    }
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [Convert]::FromBase64String($Matches[1]))
    if ($certificate.Thumbprint -ne $state.Thumbprint)
    {
        $certificate.Dispose()
        throw 'Managed certificate identity is invalid.'
    }
    return [pscustomobject]@{ State = $state; Certificate = $certificate; Hashes = $hashes }
}

function Repair-CraftCertificateTransaction($Target)
{
    $journalPath = Join-Path $Target.Path '.craft-certificate.transaction.json'
    if (-not (Test-Path -LiteralPath $journalPath)) { return }
    Assert-CraftPrivatePath $journalPath
    $journal = [System.IO.File]::ReadAllText($journalPath) | ConvertFrom-Json
    $names = @('user.pem', 'user.key', '.craft-certificate.json')
    if ($journal -isnot [pscustomobject] -or $journal.Stage -notmatch '^\.craft-certificate\.[0-9a-f]{32}$' -or
        $journal.Phase -notin @('Preparing', 'Ready'))
    {
        throw 'Invalid certificate export transaction. Preserve its files for administrator review.'
    }
    foreach ($set in @($journal.Previous, $journal.Next))
    {
        if ($null -eq $set) { continue }
        foreach ($name in $names)
        {
            if ($set.PSObject.Properties[$name].Value -notmatch '^[0-9A-F]{64}$')
            {
                throw 'Invalid certificate export transaction hashes.'
            }
        }
    }
    if ($journal.Phase -eq 'Ready' -and $null -eq $journal.Next)
    {
        throw 'Certificate export transaction has no replacement hashes.'
    }
    $stage = Join-Path $Target.Path $journal.Stage
    if (Test-Path -LiteralPath $stage) { Assert-CraftPrivatePath $stage -Directory }
    $current = [ordered]@{}
    foreach ($name in $names) { $current[$name] = Get-CraftExportHash (Join-Path $Target.Path $name) }
    $committed = $journal.Phase -eq 'Ready' -and
        @($names | Where-Object { $current[$_] -ne $journal.Next.PSObject.Properties[$_].Value }).Count -eq 0

    # Recover the complete old generation unless every replacement file reached its destination.
    if (-not $committed -and $null -ne $journal.Previous)
    {
        foreach ($name in $names)
        {
            $old = $journal.Previous.PSObject.Properties[$name].Value
            $next = if ($journal.Next) { $journal.Next.PSObject.Properties[$name].Value } else { $null }
            if ($null -ne $current[$name] -and $current[$name] -ne $old -and $current[$name] -ne $next)
            {
                throw 'Export changed during recovery. Preserve the transaction and backups for review.'
            }
            if ($current[$name] -ne $old -and
                (Get-CraftExportHash (Join-Path $stage ('old-' + $name))) -ne $old)
            {
                throw 'Export recovery needs an intact old backup. Preserve the transaction for review.'
            }
        }
        foreach ($name in $names)
        {
            if ($current[$name] -eq $journal.Previous.PSObject.Properties[$name].Value) { continue }
            $path = Join-Path $Target.Path $name
            $temporary = Join-Path $stage ('restore-' + $name)
            if (Test-Path -LiteralPath $temporary) { Assert-CraftPrivatePath $temporary; [IO.File]::Delete($temporary) }
            [IO.File]::Copy((Join-Path $stage ('old-' + $name)), $temporary, $false)
            if (Test-Path -LiteralPath $path)
            {
                [IO.File]::Replace($temporary, $path, [System.Management.Automation.Language.NullString]::Value)
            }
            else { [IO.File]::Move($temporary, $path) }
        }
    }
    elseif (-not $committed -and $journal.Phase -eq 'Ready')
    {
        # A fresh export can roll back only its own bytes; retain any competing caller-created output.
        foreach ($name in $names)
        {
            if ($current[$name] -eq $journal.Next.PSObject.Properties[$name].Value)
            {
                [System.IO.File]::Delete((Join-Path $Target.Path $name))
            }
        }
    }

    # Leave the journal until staging cleanup finishes, making repeated recovery safe.
    if (Test-Path -LiteralPath $stage)
    {
        foreach ($name in $names)
        {
            foreach ($prefix in @('', 'old-', 'restore-'))
            {
                $path = Join-Path $stage ($prefix + $name)
                if (Test-Path -LiteralPath $path)
                {
                    Assert-CraftPrivatePath $path -AllowEmpty
                    [System.IO.File]::Delete($path)
                }
            }
        }
        [System.IO.Directory]::Delete($stage, $false)
    }
    [System.IO.File]::Delete($journalPath)
    Write-Host $(if ($committed) { 'Certificate exports are complete.' } else { 'Restored interrupted export.' })
}

function Remove-CraftStoredCertificate([string]$Thumbprint)
{
    $path = 'Cert:\CurrentUser\My\' + $Thumbprint
    if (-not (Test-Path -LiteralPath $path)) { return }
    $certificate = Get-Item -LiteralPath $path
    $others = @()
    $exclusive = $false
    try
    {
        # A CSP container can hold two different public keys; compare the provider/container, not public keys.
        $identity = [Craft.CertificateKeyExporter]::KeyContainer($certificate)
        if ($identity)
        {
            $exclusive = $true
            $others = @(Get-ChildItem -LiteralPath 'Cert:\CurrentUser' -Recurse |
                Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] })
            foreach ($other in $others)
            {
                if ($other.PSPath -eq $certificate.PSPath) { continue }
                $container = [Craft.CertificateKeyExporter]::KeyContainer($other)
                if (($other.HasPrivateKey -and -not $container) -or
                    [string]::Equals($identity, $container, [StringComparison]::OrdinalIgnoreCase))
                {
                    $exclusive = $false
                    break
                }
            }
        }
        Remove-Item -LiteralPath $path -DeleteKey:$exclusive -Force -Confirm:$false -ErrorAction Stop
        Write-Host "Removed Windows certificate: $path"
        if ($certificate.HasPrivateKey -and -not $exclusive)
        {
            Write-Host 'Retained a shared private key or a key whose exclusive ownership could not be verified.'
        }
    }
    finally
    {
        foreach ($other in $others) { $other.Dispose() }
        $certificate.Dispose()
    }
}

function Complete-CraftCertificateCleanup($Target, $State, [switch]$DeleteCurrent)
{
    # Persist each requested deletion before attempting it; absent certificates are already complete.
    if ($DeleteCurrent -and $State.Thumbprint -notin $State.PendingCleanup)
    {
        $State.PendingCleanup = @($State.PendingCleanup) + $State.Thumbprint
        Save-CraftExportJson $Target '.craft-certificate.json' $State
    }
    foreach ($thumbprint in @($State.PendingCleanup))
    {
        Remove-CraftStoredCertificate $thumbprint
        $State.PendingCleanup = @($State.PendingCleanup | Where-Object { $_ -ne $thumbprint })
        Save-CraftExportJson $Target '.craft-certificate.json' $State
    }
}

function Publish-CraftCertificateExport($Target, [string]$Template, $Certificate, [byte[]]$PrivateKey, $Previous,
    [switch]$DeleteAfterExport)
{
    $names = @('user.pem', 'user.key', '.craft-certificate.json')
    $stageName = '.craft-certificate.' + [Guid]::NewGuid().ToString('N')
    $stage = Join-Path $Target.Path $stageName
    $journal = [ordered]@{
        Stage = $stageName
        Phase = 'Preparing'
        Previous = $(if ($Previous) { $Previous.Hashes } else { $null })
        Next = $null
    }

    # Record preparation before writing key material or backups so a killed process leaves recoverable intent.
    Save-CraftExportJson $Target '.craft-certificate.transaction.json' $journal
    [System.IO.Directory]::CreateDirectory($stage, $Target.DirectoryAcl) | Out-Null
    Write-CraftPem (Join-Path $stage 'user.pem') 'CERTIFICATE' $Certificate.RawData $Target.FileAcl
    Write-CraftPem (Join-Path $stage 'user.key') 'PRIVATE KEY' $PrivateKey $Target.FileAcl
    $pending = @()
    if ($Previous) { $pending += $Previous.Certificate.Thumbprint }
    if ($DeleteAfterExport) { $pending += $Certificate.Thumbprint }
    $state = [ordered]@{
        TemplateName = $Template
        Thumbprint = $Certificate.Thumbprint
        CertificateHash = Get-CraftExportHash (Join-Path $stage 'user.pem')
        PrivateKeyHash = Get-CraftExportHash (Join-Path $stage 'user.key')
        PendingCleanup = @($pending | Select-Object -Unique)
    }
    $content = $state | ConvertTo-Json -Depth 8 -Compress
    Write-CraftExportFile (Join-Path $stage '.craft-certificate.json') $content $Target.FileAcl
    $journal.Next = [ordered]@{}
    foreach ($name in $names)
    {
        $journal.Next[$name] = Get-CraftExportHash (Join-Path $stage $name)
        $path = Join-Path $Target.Path $name
        if ($Previous)
        {
            if ((Get-CraftExportHash $path) -ne $Previous.Hashes[$name])
            {
                throw 'Managed output changed during enrollment; preserve the working files.'
            }
            [System.IO.File]::Copy($path, (Join-Path $stage ('old-' + $name)), $false)
        }
        elseif (Test-Path -LiteralPath $path) { throw 'Destination changed during enrollment.' }
    }
    $journal.Phase = 'Ready'
    Save-CraftExportJson $Target '.craft-certificate.transaction.json' $journal

    # Replace individual files atomically; recovery treats all three matching hashes as the commit point.
    foreach ($name in $names)
    {
        $path = Join-Path $Target.Path $name
        if ($Previous)
        {
            [System.IO.File]::Replace((Join-Path $stage $name), $path,
                [System.Management.Automation.Language.NullString]::Value)
        }
        else { [System.IO.File]::Move((Join-Path $stage $name), $path) }
    }
    Repair-CraftCertificateTransaction $Target
    Complete-CraftCertificateCleanup $Target ([pscustomobject]$state)
}

function Invoke-CraftCertificateEnrollment($Target, [string]$Template,
    [Nullable[decimal]]$RenewBeforeDays = $null, [switch]$DeleteAfterExport)
{
    $certificatePath = Join-Path $Target.Path 'user.pem'
    $keyPath = Join-Path $Target.Path 'user.key'
    $lockPath = Join-Path $Target.Path '.craft-certificate-export.lock'
    $lock = $null
    $certificate = $null
    $previous = $null
    $privateKey = $null
    try
    {
        # Serialize recovery, issuance, publication and store cleanup in the same destination.
        if (Test-Path -LiteralPath $lockPath) { Assert-CraftPrivatePath $lockPath -AllowEmpty }
        $lock = [System.IO.FileStream]::new($lockPath, [System.IO.FileMode]::OpenOrCreate,
            [System.Security.AccessControl.FileSystemRights]('Read,Write'), [System.IO.FileShare]::None,
            4096, [System.IO.FileOptions]::None, $Target.FileAcl)
        Repair-CraftCertificateTransaction $Target
        $previous = Read-CraftExportState $Target $Template
        if ($previous)
        {
            Complete-CraftCertificateCleanup $Target $previous.State
            $statePath = Join-Path $Target.Path '.craft-certificate.json'
            $previous.Hashes['.craft-certificate.json'] = Get-CraftExportHash $statePath
            $expiration = $previous.Certificate.NotAfter.ToUniversalTime()
            $renewalStart = if ($null -eq $RenewBeforeDays) { $expiration.AddMonths(-1) }
                else { $expiration.AddDays(-[double]$RenewBeforeDays) }
            $usable = $true
            try { [Craft.CertificateKeyExporter]::ValidateProfile($previous.Certificate, $true) }
            catch { $usable = $false }
            if ($usable -and [DateTime]::UtcNow -le $renewalStart)
            {
                Write-Host "Reusing certificate valid until $($expiration.ToString('u'))."
                Complete-CraftCertificateCleanup $Target $previous.State -DeleteCurrent:$DeleteAfterExport
                Write-Output $certificatePath
                Write-Output $keyPath
                return
            }
            Write-Host 'Certificate renewal is due or the recorded certificate profile needs replacement.'
        }

        # Let Windows policy select the CA, then validate CRAFT's profile before altering existing output.
        Write-Host "Requesting template '$Template' as the signed-in user..."
        $parameters = @{ Template = $Template; Url = 'ldap:'; CertStoreLocation = 'Cert:\CurrentUser\My'
            Confirm = $false; ErrorAction = 'Stop' }
        $result = Get-Certificate @parameters
        if ([string]$result.Status -eq 'Pending')
        {
            $pending = [System.InvalidOperationException]::new(
                'Certificate approval is pending in the Windows request store; existing exports were retained.')
            $pending.Data['CraftExitCode'] = 2
            throw $pending
        }
        if ([string]$result.Status -ne 'Issued' -or $null -eq $result.Certificate)
        {
            throw "Certificate was not issued (status: $($result.Status))."
        }
        $certificate = $result.Certificate
        [Craft.CertificateKeyExporter]::ValidateProfile($certificate, $true)
        if ($previous -and $certificate.Thumbprint -eq $previous.Certificate.Thumbprint)
        {
            throw 'Enrollment did not return a replacement certificate.'
        }
        try { $privateKey = [Craft.CertificateKeyExporter]::Export($certificate) }
        catch { throw 'The private key cannot be exported. Use a template permitting exportable software keys.' }
        $publish = @{ Target = $Target; Template = $Template; Certificate = $certificate; PrivateKey = $privateKey
            Previous = $previous; DeleteAfterExport = $DeleteAfterExport }
        Publish-CraftCertificateExport @publish
        Write-Host "Issued by: $($certificate.Issuer)"
        Write-Host "Windows certificate: Cert:\CurrentUser\My\$($certificate.Thumbprint)"
        Write-Output $certificatePath
        Write-Output $keyPath
    }
    catch
    {
        if ($null -ne $lock)
        {
            try { Repair-CraftCertificateTransaction $Target }
            catch { Write-Warning "Export recovery in '$($Target.Path)' needs another retry or administrator review." }
        }
        throw
    }
    finally
    {
        if ($null -ne $privateKey) { [Array]::Clear($privateKey, 0, $privateKey.Length) }
        if ($null -ne $certificate) { $certificate.Dispose() }
        if ($null -ne $previous) { $previous.Certificate.Dispose() }
        if ($null -ne $lock) { $lock.Dispose() }
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
