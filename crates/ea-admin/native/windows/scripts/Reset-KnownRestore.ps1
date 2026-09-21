#requires -Version 7.4
#requires -PSEdition Core
# Explicit known-restore reset for the actual interactive affected account only.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InstalledBundle,
    [Parameter(Mandatory)][ValidatePattern('\AS-1-(?:[0-9]+-)+[0-9]+\z')][string]$ExpectedAccountSid,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectedInstallationId,
    [Parameter(Mandatory)][ValidateSet('win-x64','win-arm64', IgnoreCase=$false)][string]$Architecture,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\z')][string]$Version,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ExpectedCertificateSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows deployment host required' }
# Invoke from an authenticated kit using a trusted, serviced PowerShell 7.4+,
# -NoProfile, and a clean launch environment. Self-checks cannot authenticate code
# that an attacker already replaced before this script started.
$PSModuleAutoLoadingPreference = 'None'
# The path is built with [IO.Path]::Combine and NOT with Join-Path: Join-Path is
# itself exported by Microsoft.PowerShell.Management, the third module below, and
# with autoloading switched off it does not exist yet on the first iteration.
# Measured: with $PSModuleAutoLoadingPreference = 'None', Join-Path throws
# CommandNotFoundException. [IO.Path]::Combine needs no module and resolves the
# same location, so the imports still come from $PSHOME and nowhere else.
foreach ($module in @('Microsoft.PowerShell.Security','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Management')) {
    Import-Module ([IO.Path]::Combine($PSHOME, 'Modules', $module, "$module.psd1")) -Force
}
function Read-KitFile([string]$Name) {
    $path = Join-Path $PSScriptRoot $Name
    $file=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($file.Length -gt 262144 -or ([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::ReparsePoint)) { throw 'Regular bounded management file required' }
        $bytes=[byte[]]::new([int]$file.Length); $file.ReadExactly($bytes,0,$bytes.Length); return ,$bytes
    } finally { $file.Dispose() }
}
$entryName=[IO.Path]::GetFileName($PSCommandPath)
$entryBytes=Read-KitFile $entryName
$entrySignature=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -Content $entryBytes -SourcePathOrExtension '.ps1'
if ($entrySignature.Status -ne 'Valid' -or $null -eq $entrySignature.SignerCertificate) { throw 'Release-signed management entrypoint required' }
$certificateDer=$entrySignature.SignerCertificate.RawData
$certificateHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificateDer)).ToLowerInvariant()
if ($certificateHash -cne $ExpectedCertificateSha256) { throw 'Out-of-band release publisher pin mismatch' }
$kitAssets=@('ReleaseManifest.psm1','ReleaseSecurity.psm1','RestoreTransport.psm1',
    'Install-Release.ps1','Reset-KnownRestore.ps1','Configure-BackupPolicy.ps1')
$kitFiles=$kitAssets+@('ea-native-management.release.psd1','release-signer.cer')
$actual=@([IO.Directory]::GetFileSystemEntries($PSScriptRoot))
if ($actual.Count -ne $kitFiles.Count) { throw 'Closed management kit inventory required' }
foreach ($path in $actual) {
    if ([IO.Path]::GetFileName($path) -cnotin $kitFiles -or
        ([IO.File]::GetAttributes($path) -band ([IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint))) { throw 'Unexpected management kit entry' }
}
if ([Convert]::ToBase64String((Read-KitFile 'release-signer.cer')) -cne [Convert]::ToBase64String($certificateDer)) { throw 'Management certificate DER mismatch' }
$kitBytes=@{}
foreach ($name in ($kitAssets+@('ea-native-management.release.psd1'))) {
    $bytes=Read-KitFile $name
    $signature=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -Content $bytes -SourcePathOrExtension ([IO.Path]::GetExtension($name))
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
        [Convert]::ToBase64String($signature.SignerCertificate.RawData) -cne [Convert]::ToBase64String($certificateDer)) { throw 'Management file publisher mismatch' }
    $kitBytes[$name]=$bytes
}
if ([Convert]::ToBase64String($entryBytes) -cne [Convert]::ToBase64String($kitBytes[$entryName])) { throw 'Management entrypoint changed' }
# Authenticate first, then import these exact bytes. Never execute a PSD1 or
# reopen a module path between verification and execution.
$utf8=[Text.UTF8Encoding]::new($false,$true)
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($utf8.GetString($kitBytes['ea-native-management.release.psd1']).TrimStart([char]0xfeff),[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0 -or $null -ne $ast.ParamBlock -or $null -ne $ast.BeginBlock -or
    $null -ne $ast.ProcessBlock -or $null -ne $ast.DynamicParamBlock -or $null -eq $ast.EndBlock -or $ast.EndBlock.Statements.Count -ne 1) { throw 'Literal management manifest required' }
$statement=$ast.EndBlock.Statements[0]
if ($statement -isnot [Management.Automation.Language.PipelineAst] -or $statement.PipelineElements.Count -ne 1) { throw 'Literal management manifest required' }
$element=$statement.PipelineElements[0]
if ($element -isnot [Management.Automation.Language.CommandExpressionAst] -or $element.Redirections.Count -ne 0 -or
    $element.Expression -isnot [Management.Automation.Language.HashtableAst]) { throw 'Literal management manifest required' }
$kit=$element.Expression.SafeGetValue()
$keys=@('Schema','Product','Role','Version','Architecture','Assets')
foreach ($key in @('Product','Role','Version','Architecture')) {
    if ($kit[$key] -isnot [string]) { throw 'Literal management text fields required' }
}
if ($kit.Count -ne 6 -or @($kit.Keys | Where-Object { $_ -cnotin $keys }).Count -ne 0 -or
    $kit.Schema -isnot [int] -or $kit.Schema -ne 1 -or $kit.Product -cne 'org.einsatzarchiv' -or
    $kit.Role -cne 'org.einsatzarchiv.operator.management' -or $kit.Version -cne $Version -or
    $kit.Architecture -cne $Architecture -or $kit.Assets -isnot [Collections.IDictionary] -or $kit.Assets.Count -ne 6 -or
    @($kit.Assets.Keys | Where-Object { $_ -cnotin $kitAssets }).Count -ne 0) { throw 'Management release contract mismatch' }
foreach ($name in $kitAssets) {
    $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($kitBytes[$name])).ToLowerInvariant()
    if ($kit.Assets[$name] -isnot [string] -or $kit.Assets[$name] -cnotmatch '\A[0-9a-f]{64}\z' -or $kit.Assets[$name] -cne $hash) { throw 'Management release digest mismatch' }
}
foreach ($name in @('ReleaseManifest.psm1','ReleaseSecurity.psm1','RestoreTransport.psm1')) {
    New-Module -Name ('Ea'+[IO.Path]::GetFileNameWithoutExtension($name)) -ScriptBlock ([ScriptBlock]::Create($utf8.GetString($kitBytes[$name]).TrimStart([char]0xfeff))) |
        Import-Module -Global -Force
}

Initialize-EaRestoreTransport
[Ea.Release.RestoreTransport]::RequireAccount($ExpectedAccountSid)
$release=Open-EaReleaseBundle $InstalledBundle $Architecture $Version $certificateDer -RequireProtected
try {
    [Ea.Release.RestoreTransport]::Reset($release.Files['ea-native-operator.exe'].Path,$ExpectedInstallationId,$ExpectedAccountSid)
    Write-Output 'Affected-account installation namespace invalidated after native fresh presence. Old slots were not enumerated or deleted. Explicit new provisioning is required.'
} finally { Close-EaReleaseBundle $release }
