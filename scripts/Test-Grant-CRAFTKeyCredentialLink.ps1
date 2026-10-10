# Offline checks only: extract helpers and the parameter block without touching Active Directory.
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.DirectoryServices -ErrorAction SilentlyContinue
$scriptPath = Join-Path $PSScriptRoot "Grant-CRAFTKeyCredentialLink.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors.Message -join "`n") }

foreach ($name in @("New-KeyCredentialRule", "Test-KeyCredentialRule", "Resolve-Account", "Assert-UnprivilegedTarget"))
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

$attribute = [Guid]"5b47d60f-6090-40b2-9f37-2a4de88f3063"
$userClass = [Guid]"bf967aba-0de6-11d0-a285-00aa003049e2"
$otherAttribute = [Guid]"28630ebf-41d5-11d1-a9c1-0000f80367c1" # a different property GUID
$sid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-21-111-222-333-1104")
$otherSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-21-111-222-333-1105")

& {
    # An OU delegation inherits the single-attribute write to descendant user objects only.
    $ouRule = New-KeyCredentialRule $sid $attribute $userClass $true
    $writeProperty = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
    $readProperty = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
    Assert ($ouRule.ObjectType -eq $attribute) "OU rule targets the wrong attribute."
    Assert ($ouRule.InheritedObjectType -eq $userClass) "OU rule is not scoped to the user class."
    Assert ($ouRule.InheritanceType -eq
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents) "OU rule does not inherit."
    Assert ($ouRule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) "OU rule is not Allow."
    # The rights must be exactly ReadProperty + WriteProperty: no extended, generic or control rights.
    $exact = [int]$readProperty -bor [int]$writeProperty
    Assert ([int]$ouRule.ActiveDirectoryRights -eq $exact) "OU rule grants more than the single-attribute read/write."

    # A user delegation applies to that object with no inheritance.
    $userRule = New-KeyCredentialRule $sid $attribute $userClass $false
    Assert ($userRule.InheritanceType -eq
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None) "User rule must not inherit."
    Assert ($userRule.ObjectType -eq $attribute) "User rule targets the wrong attribute."
    Write-Host "PASS: least-privilege access rule construction"

    # Existing ACEs with different scopes must neither suppress the grant nor be removed by this helper.
    Assert (Test-KeyCredentialRule $ouRule $ouRule) "Matcher rejected its own rule."
    Assert (Test-KeyCredentialRule $userRule $userRule) "Matcher rejected the user rule."
    $otherTrustee = New-KeyCredentialRule $otherSid $attribute $userClass $true
    $otherProperty = New-KeyCredentialRule $sid $otherAttribute $userClass $true
    Assert (-not (Test-KeyCredentialRule $otherTrustee $ouRule)) "Matcher accepted a different trustee."
    Assert (-not (Test-KeyCredentialRule $otherProperty $ouRule)) "Matcher accepted a different attribute."
    Assert (-not (Test-KeyCredentialRule $userRule $ouRule)) "An OU-only ACE suppressed descendant delegation."
    $computerRule = New-KeyCredentialRule $sid $attribute ([Guid]"bf967a86-0de6-11d0-a285-00aa003049e2") $true
    Assert (-not (Test-KeyCredentialRule $computerRule $ouRule)) "A computer ACE matched user delegation."
    $broaderRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid,
        [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty, WriteProperty, ExtendedRight",
        [System.Security.AccessControl.AccessControlType]::Allow, $attribute,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents, $userClass)
    Assert (-not (Test-KeyCredentialRule $broaderRule $ouRule)) "Matcher accepted broader rights."
    $inheritedAcl = [System.DirectoryServices.ActiveDirectorySecurity]::new()
    $inheritedAcl.SetSecurityDescriptorSddlForm("D:(OA;CIIOID;RPWP;$attribute;$userClass;$($sid.Value))")
    $inheritedRule = @($inheritedAcl.GetAccessRules($true, $true,
        [System.Security.Principal.SecurityIdentifier]))[0]
    Assert (-not (Test-KeyCredentialRule $inheritedRule $ouRule)) "Matcher accepted an inherited rule."
    $deny = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid,
        [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty, WriteProperty",
        [System.Security.AccessControl.AccessControlType]::Deny, $attribute,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    Assert (-not (Test-KeyCredentialRule $deny $userRule)) "Matcher accepted a Deny rule."
    $readOnly = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid,
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
        [System.Security.AccessControl.AccessControlType]::Allow, $attribute,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
    Assert (-not (Test-KeyCredentialRule $readOnly $userRule)) "Matcher accepted a read-only rule."
    Write-Host "PASS: delegation rule matching"
}

& {
    # The two targets are mutually exclusive; a [Parameter] attribute makes the function advanced.
    $probe = [scriptblock]::Create("function Invoke-ParamProbe { " + $ast.ParamBlock.Extent.Text +
        "`n `$PSCmdlet.ParameterSetName }")
    . $probe
    Assert ((Invoke-ParamProbe -ServiceAccount svc -TargetOU "OU=x,DC=d,DC=l") -eq "OU") "OU parameter set unresolved."
    Assert ((Invoke-ParamProbe -ServiceAccount svc -TargetUser alice) -eq "User") "User parameter set unresolved."
    $rejected = $false
    try { Invoke-ParamProbe -ServiceAccount svc -TargetOU "OU=x" -TargetUser alice | Out-Null }
    catch { $rejected = $true }
    Assert $rejected "A single target scope was not enforced."
    Write-Host "PASS: mutually exclusive target parameters"
}

& {
    # Exercise UPN lookup through mocked directory cmdlets, including ambiguity and LDAP filter escaping.
    $fixtureQueries = [System.Collections.Generic.List[string]]::new()
    $fixtureAccount = [pscustomobject]@{ SamAccountName = "alice"; DistinguishedName = "CN=alice,DC=fixture" }
    $fixtureResults = @($fixtureAccount)
    function Get-ADUser
    {
        param($Identity, $LDAPFilter, $ErrorAction)
        if ($Identity) { return $fixtureAccount }
        $fixtureQueries.Add($LDAPFilter)
        return $fixtureResults
    }
    function Get-ADServiceAccount { param($LDAPFilter, $ErrorAction) }
    function Get-ADComputer { param($LDAPFilter, $ErrorAction) }
    Assert ((Resolve-Account "alice@fixture.invalid").SamAccountName -eq "alice") "UPN lookup failed."
    Assert ($fixtureQueries[0] -eq "(userPrincipalName=alice@fixture.invalid)") "UPN was not searched as an attribute."
    Assert ((Resolve-Account "CN=alice@example,DC=fixture" $true).SamAccountName -eq "alice") "DN was mistaken for a UPN."
    [void](Resolve-Account 'alice*)(x=*)@fixture.invalid' $true)
    Assert ($fixtureQueries[1] -eq '(userPrincipalName=alice\2a\29\28x=\2a\29@fixture.invalid)') "UPN filter injection was possible."
    foreach ($count in @(0, 2))
    {
        $fixtureResults = @()
        for ($i = 0; $i -lt $count; $i++) { $fixtureResults += $fixtureAccount }
        $rejected = $false
        try { Resolve-Account "alice@fixture.invalid" $true | Out-Null }
        catch { $rejected = $_.Exception.Message -like "*exactly one account*" }
        Assert $rejected "Missing or ambiguous UPN was accepted."
    }
    Write-Host "PASS: UPN resolution and escaped directory searches"
}

& {
    # Model actual binary SID attributes and an OU containing a newly privileged user.
    $fixtureDomainSid = "S-1-5-21-111-222-333"
    $fixtureSids = @{}
    foreach ($rid in @(512, 513, 519))
    {
        $sidObject = [System.Security.Principal.SecurityIdentifier]::new("$fixtureDomainSid-$rid")
        $sidBytes = [byte[]]::new($sidObject.BinaryLength)
        $sidObject.GetBinaryForm($sidBytes, 0)
        $fixtureSids[$rid] = $sidBytes
    }
    $fixtureUsers = @{}
    for ($i = 0; $i -lt 27; $i++)
    {
        $dn = "CN=user$i,OU=fixture,DC=fixture"
        $fixtureUsers[$dn] = [pscustomobject]@{
            DistinguishedName = $dn; SamAccountName = "user$i"; adminCount = 0; primaryGroupID = 513
            SID = [System.Security.Principal.SecurityIdentifier]::new("$fixtureDomainSid-$(1100 + $i)")
            tokenGroups = @(,$fixtureSids[513]); SIDHistory = @()
        }
    }
    function Get-ADDomain
    {
        param($Identity)
        [pscustomobject]@{ DomainSID = [System.Security.Principal.SecurityIdentifier]::new($fixtureDomainSid) }
    }
    function Get-ADForest { [pscustomobject]@{ RootDomain = "fixture.invalid" } }
    function Get-ADUser
    {
        param($Identity, $Properties, $SearchBase, $SearchScope, $LDAPFilter)
        if ($Identity) { return $fixtureUsers[$Identity] }
        Assert ($LDAPFilter -ne "(adminCount=1)") "OU scan still relies only on adminCount."
        return @($fixtureUsers.Values)
    }
    function Write-Warn { param($Message) }
    $target = $fixtureUsers["CN=user0,OU=fixture,DC=fixture"]
    Assert-UnprivilegedTarget $target.DistinguishedName $true $false
    Assert-UnprivilegedTarget "OU=fixture,DC=fixture" $false $false
    $target.tokenGroups = @(,$fixtureSids[512])
    foreach ($isUser in @($true, $false))
    {
        $rejected = $false
        try { Assert-UnprivilegedTarget $target.DistinguishedName $isUser $false }
        catch { $rejected = $_.Exception.Message -like "*privileged SID*" }
        Assert $rejected "Binary Domain Admins membership with adminCount=0 was accepted."
    }
    Assert-UnprivilegedTarget $target.DistinguishedName $true $true
    $target.tokenGroups = @(,$fixtureSids[513])
    foreach ($case in @("primaryGroupID", "SIDHistory", "SID", "tokenGroups"))
    {
        $original = $target.$case
        switch ($case)
        {
            "primaryGroupID" { $target.primaryGroupID = 512 }
            "SIDHistory" { $target.SIDHistory = @(,$fixtureSids[519]) }
            "SID" { $target.SID = [System.Security.Principal.SecurityIdentifier]::new("$fixtureDomainSid-500") }
            "tokenGroups" { $target.tokenGroups = @() }
        }
        $rejected = $false
        try { Assert-UnprivilegedTarget $target.DistinguishedName $true $false }
        catch { $rejected = $_.Exception.Message -like "Refusing a privileged target*" }
        Assert $rejected "Privilege or unavailable membership was accepted for $case."
        $target.$case = $original
    }
    Write-Host "PASS: privileged membership checks for users and entire OUs"
}

Write-Host "`nAll offline delegation checks passed. No Active Directory objects were read or modified."
