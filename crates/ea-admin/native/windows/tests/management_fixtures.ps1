# Pure data/compilation tests. Never calls signing, installation, native account
# APIs, helper Reset(), backup policy or the production process transport.
#requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../scripts/ReleaseManifest.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../scripts/ReleaseSecurity.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../scripts/RestoreTransport.psm1') -Force
$count=0
function Check([bool]$condition) {
    if (-not $condition) { throw "Management fixture $($script:count+1) failed, caller line $((Get-PSCallStack)[1].ScriptLineNumber)" }
    $script:count++
}
function Refused([scriptblock]$operation) {
    $refused=$false; try { & $operation | Out-Null } catch { $refused=$true }; Check $refused
}
Initialize-EaReleaseNative
Initialize-EaRestoreTransport
Check ($null -ne ('Ea.Release.Native' -as [type]))
Check ($null -ne ('Ea.Release.RestoreTransport' -as [type]))
$id='a'*64
# S-1-5-21-1-2-3-1001 in actual binary SID layout, independent of this host.
$sid=[byte[]]@(1,5,0,0,0,0,0,5,21,0,0,0,1,0,0,0,2,0,0,0,3,0,0,0,233,3,0,0)
$account=@{ok=$true;installation_id=$id;platform='windows';sid=[Convert]::ToHexString($sid).ToLowerInvariant();identifier_authority='000000000005';subauthorities=@(21,1,2,3,1001);locked=$false}
function Encode($value) { return ,[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $value -Compress -Depth 4)) }
[Ea.Release.RestoreTransport]::CheckResponse((Encode $account),'account',$id,$sid); Check $true
$reset=@{ok=$true;installation_id=$id;reset=$true}
[Ea.Release.RestoreTransport]::CheckResponse((Encode $reset),'reset',$id,$sid); Check $true
foreach ($change in @(@{ok=$false},@{ok='true'},@{installation_id=('b'*64)},@{platform='linux'},@{locked=$true},
    @{locked='false'},@{sid='0100'},@{identifier_authority='000000000004'},@{subauthorities=@(21,1,2,3,1002)},
    @{subauthorities=@(21,1,2,3)},@{extra='unexpected'})) {
    $bad=$account.Clone(); foreach ($key in $change.Keys) { $bad[$key]=$change[$key] }
    Refused { [Ea.Release.RestoreTransport]::CheckResponse((Encode $bad),'account',$id,$sid) }
}
foreach ($key in @($account.Keys)) {
    $bad=$account.Clone(); $bad.Remove($key)
    Refused { [Ea.Release.RestoreTransport]::CheckResponse((Encode $bad),'account',$id,$sid) }
}
foreach ($bad in @(@{ok=$true;installation_id=$id;reset=$false},@{ok=$true;installation_id=$id;reset='true'},
    @{ok=$true;installation_id=$id;reset=$true;extra=1},@{ok=$true;installation_id=('b'*64);reset=$true})) {
    Refused { [Ea.Release.RestoreTransport]::CheckResponse((Encode $bad),'reset',$id,$sid) }
}
foreach ($bad in @('{"ok":true,"ok":true}', '[1]', '{}', 'null', '{"ok":true}{}')) {
    Refused { [Ea.Release.RestoreTransport]::CheckResponse([Text.Encoding]::UTF8.GetBytes($bad),'reset',$id,$sid) }
}
Refused { [Ea.Release.RestoreTransport]::CheckResponse((Encode $account),'sign',$id,$sid) }
Refused { [Ea.Release.RestoreTransport]::CheckResponse((Encode $account),'account',$id,[byte[]]@(1,16)) }

# Verify the actual entrypoint bootstrap boundary using its AST, without invoking
# signature APIs or importing unverified code. All three imports must follow the
# release-role and digest checks; both entrypoints share byte-identical bootstrap.
$bootstraps=@()
foreach ($name in @('Install-Release.ps1','Reset-KnownRestore.ps1')) {
    $source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot "../scripts/$name"))
    $start=$source.IndexOf('Set-StrictMode -Version Latest')
    $end=$source.IndexOf("`nInitialize-Ea",$start)
    if ($name -eq 'Install-Release.ps1') { $end=$source.IndexOf("`n`$identity=",$start) }
    $bootstrap=$source.Substring($start,$end-$start); $bootstraps+=,$bootstrap
    Check ($bootstrap.IndexOf('Management release digest mismatch') -lt $bootstrap.IndexOf('New-Module -Name'))
    Check ($bootstrap.IndexOf('Out-of-band release publisher pin mismatch') -lt $bootstrap.IndexOf('New-Module -Name'))
    Check (-not $source.Contains('SkipVerify') -and -not $source.Contains('AllowUnsigned'))
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        $parameters=@{Architecture='win-x64'; Version='0.1.0'; ExpectedCertificateSha256=('0'*64)}
        if ($name -eq 'Install-Release.ps1') { $parameters.Bundle='unused'; $parameters.Destination='unused' }
        else { $parameters.InstalledBundle='unused'; $parameters.ExpectedAccountSid='S-1-5-21-1-2-3-1001'; $parameters.ExpectedInstallationId=$id }
        Refused { & (Join-Path $PSScriptRoot "../scripts/$name") @parameters }
    }
}
Check ($bootstraps[0] -ceq $bootstraps[1])
Write-Output "$count management fixture checks passed; embedded C# compiled, no native methods or credentials invoked."
