#requires -Version 7.4
# Pure packaging fixtures: no certificate store, signature operation or installation.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../scripts/ReleaseManifest.psm1') -Force
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('ea-release-fixture-' + [Guid]::NewGuid().ToString('N'))
$count = 0
function Check([bool]$condition) {
    if (-not $condition) { throw "Release manifest fixture failed at check $($script:count + 1), caller line $((Get-PSCallStack)[1].ScriptLineNumber)" }
    $script:count++
}
function Refused([scriptblock]$operation) {
    $refused = $false
    try { & $operation | Out-Null } catch { $refused = $true }
    Check $refused
}
try {
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    $bundle = Join-Path $fixtureRoot 'bundle'
    New-Item -ItemType Directory -Path $bundle | Out-Null
    foreach ($asset in Get-EaReleaseAssets) { [IO.File]::WriteAllBytes((Join-Path $bundle $asset), [Text.Encoding]::ASCII.GetBytes($asset)) }
    foreach ($architecture in @('win-x64', 'win-arm64')) {
        $text = New-EaReleaseManifest -Bundle $bundle -Architecture $architecture -Version '0.1.0'
        $path = Join-Path $fixtureRoot 'manifest.psd1'
        [IO.File]::WriteAllText($path, $text)
        $manifest = Import-PowerShellDataFile -LiteralPath $path
        Assert-EaReleaseManifest -Manifest $manifest -Architecture $architecture -Version '0.1.0' -Hashes $manifest.Assets
        Check ($manifest.Count -eq 7 -and $manifest.Schema -eq 1)
        Check ($manifest.Product -ceq 'org.einsatzarchiv' -and $manifest.ParentRole -ceq 'org.einsatzarchiv.cli' -and $manifest.HelperRole -ceq 'org.einsatzarchiv.operator.native')
        Check ($manifest.Version -ceq '0.1.0' -and $manifest.Architecture -ceq $architecture)
        Check ($manifest.Assets.Count -eq 9)
        foreach ($asset in Get-EaReleaseAssets) {
            Check ($manifest.Assets[$asset] -ceq (Get-FileHash -LiteralPath (Join-Path $bundle $asset) -Algorithm SHA256).Hash.ToLowerInvariant())
        }
    }
    $before = New-EaReleaseManifest -Bundle $bundle -Architecture win-x64 -Version '0.1.0'
    [IO.File]::AppendAllText((Join-Path $bundle 'libsodium.dll'), 'changed-library')
    $after = New-EaReleaseManifest -Bundle $bundle -Architecture win-x64 -Version '0.1.0'
    Check ($before -cne $after)
    $valid = Read-EaDataBytes -Bytes ([Text.Encoding]::UTF8.GetBytes($before))
    Assert-EaReleaseManifest $valid win-x64 '0.1.0' $valid.Assets
    Check ($valid.Count -eq 7)
    foreach ($field in @('Schema','Product','ParentRole','HelperRole','Version','Architecture','Assets')) {
        $bad = $valid.Clone(); $bad.Remove($field)
        Refused { Assert-EaReleaseManifest $bad win-x64 '0.1.0' $valid.Assets }
    }
    foreach ($change in @(@{Schema='1'}, @{Schema=1.0}, @{Product='other'}, @{ParentRole='other'},
        @{HelperRole='other'}, @{Version='0.1.1'}, @{Architecture='win-arm64'}, @{Extra=1})) {
        $bad = $valid.Clone(); foreach ($key in $change.Keys) { $bad[$key] = $change[$key] }
        Refused { Assert-EaReleaseManifest $bad win-x64 '0.1.0' $valid.Assets }
    }
    $bad = $valid.Clone(); $bad.Remove('Schema'); $bad['schema'] = 1
    Refused { Assert-EaReleaseManifest $bad win-x64 '0.1.0' $valid.Assets }
    foreach ($field in @('Product','ParentRole','HelperRole','Version','Architecture')) {
        $bad = $valid.Clone(); $bad[$field] = @($valid[$field])
        Refused { Assert-EaReleaseManifest $bad win-x64 '0.1.0' $valid.Assets }
    }
    foreach ($hash in @(('a' * 63), ('A' * 64), ('0' * 64), 42, @('a' * 64))) {
        $bad = $valid.Clone(); $bad.Assets = $valid.Assets.Clone(); $bad.Assets['libsodium.dll'] = $hash
        Refused { Assert-EaReleaseManifest $bad win-x64 '0.1.0' $valid.Assets }
    }
    foreach ($unsafe in @('@{a=$(throw "executed")}', '@{a=1}; throw "executed"',
        'Get-Item .', '@{a=[Environment]::MachineName}', '@{a=1;a=2}', "@{a=1} > 'unexpected'")) {
        Refused { Read-EaDataBytes ([Text.Encoding]::UTF8.GetBytes($unsafe)) }
    }
    Refused { Read-EaDataBytes ([byte[]]@(0xc0,0xaf)) }
    Refused { Read-EaDataBytes ([byte[]]::new(65537)) }
    Refused { New-EaReleaseManifest -Bundle $bundle -Architecture win-x64 -Version "0.1.0`n" }
    foreach ($machine in @(0x8664,0xaa64)) {
        $pe = [byte[]]::new(256); $pe[0]=0x4d; $pe[1]=0x5a; $pe[60]=128; $pe[128]=0x50; $pe[129]=0x45
        [BitConverter]::GetBytes([uint16]$machine).CopyTo($pe,132)
        $stream = [IO.MemoryStream]::new($pe)
        try { Check ((Get-EaPeMachine $stream) -eq $machine); Check ($stream.Position -eq 0) } finally { $stream.Dispose() }
    }
    foreach ($badPe in @([byte[]]::new(63), [byte[]]::new(256))) {
        $stream = [IO.MemoryStream]::new($badPe)
        try { Refused { Get-EaPeMachine $stream } } finally { $stream.Dispose() }
    }
    foreach ($owner in @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')) {
        Assert-EaAclPolicy $owner $true @(); Check $true
    }
    Refused { Assert-EaAclPolicy 'S-1-5-21-1-2-3-1001' $true @() }
    Refused { Assert-EaAclPolicy 'S-1-5-18' $false @() }
    foreach ($right in @(2,4,16,64,256,65536,262144,524288,0x10000000,0x40000000)) {
        $rule = @{Allow=$true; InheritOnly=$false; Rights=$right; Sid='S-1-1-0'}
        Refused { Assert-EaAclPolicy 'S-1-5-18' $true @($rule) }
        $rule.InheritOnly=$true; Assert-EaAclPolicy 'S-1-5-18' $true @($rule); Check $true
        $rule.InheritOnly=$false; $rule.Allow=$false; Assert-EaAclPolicy 'S-1-5-18' $true @($rule); Check $true
    }
    $rule = @{Allow=$true; InheritOnly=$false; Rights=6; Sid='S-1-1-0'}
    Assert-EaAclPolicy 'S-1-5-18' $true @($rule) -VolumeRoot; Check $true
    $rule.Rights=64; Refused { Assert-EaAclPolicy 'S-1-5-18' $true @($rule) -VolumeRoot }
    Refused { New-EaReleaseManifest -Bundle $bundle -Architecture win-x86 -Version '0.1.0' }
    Refused { New-EaReleaseManifest -Bundle $bundle -Architecture WIN-X64 -Version '0.1.0' }
    Refused { New-EaReleaseManifest -Bundle $bundle -Architecture win-x64 -Version "0.1.0'; Write-Output injected; '" }
    $extra = Join-Path $bundle 'startup-hook.dll'
    [IO.File]::WriteAllText($extra, 'unexpected')
    Refused { New-EaReleaseManifest -Bundle $bundle -Architecture win-x64 -Version '0.1.0' }
    foreach ($scriptName in @('ReleaseManifest.psm1','ReleaseSecurity.psm1','RestoreTransport.psm1',
        'Package.ps1','Sign-Release.ps1','Install-Release.ps1','Reset-KnownRestore.ps1','Configure-BackupPolicy.ps1')) {
        $scriptPath = Join-Path $PSScriptRoot "../scripts/$scriptName"
        Check ([IO.File]::Exists($scriptPath))
        $tokens=$null; $errors=$null
        [void][Management.Automation.Language.Parser]::ParseFile($scriptPath,[ref]$tokens,[ref]$errors)
        Check ($errors.Count -eq 0)
    }
    Remove-Item -LiteralPath $extra
    Remove-Item -LiteralPath (Join-Path $bundle 'ea-native-operator.runtimeconfig.json')
    Refused { New-EaReleaseManifest -Bundle $bundle -Architecture win-x64 -Version '0.1.0' }
    New-Item -ItemType Directory -Path (Join-Path $bundle 'ea-native-operator.runtimeconfig.json') | Out-Null
    Refused { New-EaReleaseManifest -Bundle $bundle -Architecture win-x64 -Version '0.1.0' }
    Write-Output "$count release manifest checks passed; no native signing or state accessed."
} finally {
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
}
