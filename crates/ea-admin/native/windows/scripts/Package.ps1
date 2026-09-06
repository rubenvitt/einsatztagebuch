#requires -Version 7.4
#requires -PSEdition Core
[CmdletBinding()]
param(
    [ValidateSet('win-x64', 'win-arm64', IgnoreCase=$false)][string]$Runtime = 'win-x64',
    [Parameter(Mandatory)][string]$VCRedistPath,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-fA-F]{64}\z')][string]$VCRedistSha256
)
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows package staging host required' }
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$root = Split-Path $PSScriptRoot -Parent
$redist = (Resolve-Path -LiteralPath $VCRedistPath).Path
if ((Get-FileHash -LiteralPath $redist -Algorithm SHA256).Hash -ne $VCRedistSha256) { throw 'VC++ redistributable hash mismatch' }
$signature = Get-AuthenticodeSignature -LiteralPath $redist
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation[, ]') { throw 'Microsoft VC++ signature required' }
$expectedName = if ($Runtime -eq 'win-x64') { 'vc_redist.x64.exe' } else { 'vc_redist.arm64.exe' }
if ([IO.Path]::GetFileName($redist) -ne $expectedName) { throw 'Select the matching Microsoft redistributable architecture' }
$output = Join-Path $root "artifacts/$Runtime"
if (Test-Path -LiteralPath $output) { throw 'Use a fresh artifacts directory to avoid stale package contents' }
& dotnet restore (Join-Path $root 'ea-native-operator.csproj') --locked-mode
if ($LASTEXITCODE -ne 0) { throw 'Locked restore failed' }
& dotnet publish (Join-Path $root 'ea-native-operator.csproj') -c Release -r $Runtime --self-contained false --no-restore -p:UseSharedCompilation=false -o $output
if ($LASTEXITCODE -ne 0) { throw 'Publish failed' }
foreach ($file in @('ea-native-operator.exe', 'ea-native-operator.dll', 'ea-native-operator.deps.json', 'ea-native-operator.runtimeconfig.json', 'NSec.Cryptography.dll', 'libsodium.dll', 'WinRT.Runtime.dll', 'Microsoft.Windows.SDK.NET.dll')) {
    if (-not (Test-Path -LiteralPath (Join-Path $output $file))) { throw "Missing package asset: $file" }
}
Copy-Item -LiteralPath $redist -Destination (Join-Path $output $expectedName)
Copy-Item -LiteralPath (Join-Path $root 'README.md'), (Join-Path $root 'DEPENDENCIES.md'), (Join-Path $root 'ACCEPTANCE.md'), (Join-Path $root 'RELEASE-TRUST.md'), (Join-Path $root 'packages.lock.json') -Destination $output
Copy-Item -LiteralPath (Join-Path $root 'licenses') -Destination $output -Recurse
$managementSource=Join-Path $output 'management-source'
New-Item -ItemType Directory -Path $managementSource | Out-Null
foreach ($script in @('ReleaseManifest.psm1','ReleaseSecurity.psm1','RestoreTransport.psm1','Sign-Release.ps1',
    'Install-Release.ps1','Reset-KnownRestore.ps1','Configure-BackupPolicy.ps1')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $script) -Destination $managementSource
}
Get-ChildItem -LiteralPath $output -File -Recurse | Get-FileHash -Algorithm SHA256 | ForEach-Object {
    "$($_.Hash.ToLowerInvariant())  $([IO.Path]::GetRelativePath($output, $_.Path))"
} | Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS') -Encoding utf8
# This is unsigned staging for Sign-Release.ps1. Docs/licenses/redist and the
# management kit stay OUTSIDE the installed ten-file sibling bundle. Runtime
# deployment and actual backup-policy configuration are explicit target tasks;
# packaging never installs runtimes, signs files or changes OS policy.
