#requires -Version 7.4
#requires -PSEdition Core
# Explicit release signing on the trusted build host, never normal operator/CI work.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ParentBinary,
    [Parameter(Mandatory)][string]$HelperPackage,
    [Parameter(Mandatory)][string]$Destination,
    [Parameter(Mandatory)][string]$ManagementDestination,
    [Parameter(Mandatory)][ValidateSet('win-x64','win-arm64', IgnoreCase=$false)][string]$Architecture,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\z')][string]$Version,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-fA-F]{40}\z')][string]$CertificateThumbprint,
    [uri]$TimestampServer
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows release signer required' }
Import-Module (Join-Path $PSScriptRoot 'ReleaseManifest.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ReleaseSecurity.psm1') -Force
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint"
$codeSigning=$false
foreach ($extension in $certificate.Extensions) {
    if ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
        foreach ($usage in $extension.EnhancedKeyUsages) { if ($usage.Value -eq '1.3.6.1.5.5.7.3.3') { $codeSigning=$true } }
    }
}
if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -le [DateTime]::Now -or
    $certificate.NotBefore -gt [DateTime]::Now -or -not $codeSigning) {
    throw 'Explicit current code-signing certificate with existing private key required'
}
if ($null -ne $TimestampServer -and (-not $TimestampServer.IsAbsoluteUri -or $TimestampServer.Scheme -notin @('https','http'))) { throw 'Explicit HTTP(S) timestamp service required' }
$certificateDer=$certificate.RawData
$destinations=@([IO.Path]::GetFullPath($Destination),[IO.Path]::GetFullPath($ManagementDestination))
if ([String]::Equals($destinations[0],$destinations[1],[StringComparison]::OrdinalIgnoreCase)) { throw 'Separate bundle and management destinations required' }
foreach ($path in $destinations) {
    if (Test-Path -LiteralPath $path) { throw 'Fresh destination required; inputs are never signed in place' }
    if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($path)) -PathType Container)) { throw 'Existing destination parent required' }
}
$Destination=$destinations[0]; $ManagementDestination=$destinations[1]
$inputs=@{}; $held=[Collections.Generic.List[IDisposable]]::new(); $verified=$null
$kitAssets=@('ReleaseManifest.psm1','ReleaseSecurity.psm1','RestoreTransport.psm1',
    'Install-Release.ps1','Reset-KnownRestore.ps1','Configure-BackupPolicy.ps1')
function Sign-Output([string]$Path) {
    $parameters=@{LiteralPath=$Path; Certificate=$certificate; HashAlgorithm='SHA256'}
    if ($null -ne $TimestampServer) { $parameters.TimestampServer=$TimestampServer.AbsoluteUri }
    $signed=Microsoft.PowerShell.Security\Set-AuthenticodeSignature @parameters
    if ($signed.Status -ne 'Valid' -or ($null -ne $TimestampServer -and $null -eq $signed.TimeStamperCertificate)) { throw 'Release signing/timestamp verification failed' }
    Assert-EaFileSigner $Path $certificateDer
}
try {
    foreach ($asset in Get-EaReleaseAssets) {
        $path=if ($asset -eq 'einsatzarchiv.exe') { $ParentBinary } else { Join-Path $HelperPackage $asset }
        $item=Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Regular release input required' }
        $stream=[IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $held.Add($stream); $inputs[$asset]=$stream
    }
    $machine=if ($Architecture -eq 'win-x64') { 0x8664 } else { 0xaa64 }
    foreach ($name in @('einsatzarchiv.exe','ea-native-operator.exe')) {
        if ((Get-EaPeMachine $inputs[$name]) -ne $machine) { throw 'Parent/helper architecture mismatch' }
    }
    # Read reviewed management source before producing outputs. There is no
    # certificate import, key creation, default signer or developer bypass.
    $kitSource=@{}
    foreach ($name in $kitAssets) {
        $path=Join-Path $PSScriptRoot $name
        $item=Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 262144) { throw 'Regular management source required' }
        $kitSource[$name]=[IO.File]::ReadAllText($path,[Text.UTF8Encoding]::new($false,$true))
    }
    New-Item -ItemType Directory -Path $Destination -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path $ManagementDestination -ErrorAction Stop | Out-Null
    foreach ($asset in Get-EaReleaseAssets) {
        $target=[IO.File]::Open((Join-Path $Destination $asset),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $inputs[$asset].Position=0; $inputs[$asset].CopyTo($target); $target.Flush($true) } finally { $target.Dispose() }
    }
    # Third-party DLLs retain their signatures and are bound by manifest hashes.
    foreach ($asset in @('einsatzarchiv.exe','ea-native-operator.exe')) { Sign-Output (Join-Path $Destination $asset) }
    $manifest=New-EaReleaseManifest $Destination $Architecture $Version
    $manifestPath=Join-Path $Destination 'ea-native-operator.release.psd1'
    [IO.File]::WriteAllText($manifestPath,$manifest,[Text.UTF8Encoding]::new($true))
    Sign-Output $manifestPath
    $verified=Open-EaReleaseBundle $Destination $Architecture $Version $certificateDer

    $hashes=@{}
    foreach ($name in $kitAssets) {
        $path=Join-Path $ManagementDestination $name
        [IO.File]::WriteAllText($path,$kitSource[$name],[Text.UTF8Encoding]::new($true))
        Sign-Output $path
        $signature=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -Content ([IO.File]::ReadAllBytes($path)) -SourcePathOrExtension ([IO.Path]::GetExtension($name))
        if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
            [Convert]::ToBase64String($signature.SignerCertificate.RawData) -cne [Convert]::ToBase64String($certificateDer)) { throw 'Management byte signature verification failed' }
        $hashes[$name]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $lines=@('@{','    Schema = 1',"    Product = 'org.einsatzarchiv'", "    Role = 'org.einsatzarchiv.operator.management'",
        "    Version = '$Version'", "    Architecture = '$Architecture'", '    Assets = @{')
    foreach ($name in $kitAssets) { $lines+="        '$name' = '$($hashes[$name])'" }
    $lines+=@('    }','}')
    $path=Join-Path $ManagementDestination 'ea-native-management.release.psd1'
    [IO.File]::WriteAllText($path,($lines -join [Environment]::NewLine)+[Environment]::NewLine,[Text.UTF8Encoding]::new($true))
    Sign-Output $path
    [IO.File]::WriteAllBytes((Join-Path $ManagementDestination 'release-signer.cer'),$certificateDer)
    $pin=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($certificateDer)).ToLowerInvariant()
    Write-Output "Signed ten-file bundle and separate eight-file management kit created. Distribute this public DER SHA-256 pin through a trusted independent channel: $pin"
} catch {
    Write-Warning 'Do not use incomplete output directories. No original input or existing installation is removed.'
    throw
} finally {
    if ($null -ne $verified) { Close-EaReleaseBundle $verified }
    foreach ($stream in $held) { $stream.Dispose() }
    $certificate.Dispose()
}
