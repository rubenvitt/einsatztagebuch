Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EaReleaseAssets {
    @('einsatzarchiv.exe', 'ea-native-operator.exe', 'ea-native-operator.dll',
      'ea-native-operator.deps.json', 'ea-native-operator.runtimeconfig.json',
      'NSec.Cryptography.dll', 'libsodium.dll', 'WinRT.Runtime.dll',
      'Microsoft.Windows.SDK.NET.dll')
}

function New-EaReleaseManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Bundle,
        [Parameter(Mandatory)][ValidateSet('win-x64', 'win-arm64', IgnoreCase=$false)][string]$Architecture,
        [Parameter(Mandatory)][ValidatePattern('\A[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\z')][string]$Version
    )
    $directory = Get-Item -LiteralPath $Bundle -Force
    if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Release bundle must be a regular directory'
    }
    $expected = @(Get-EaReleaseAssets)
    $actual = @(Get-ChildItem -LiteralPath $Bundle -Force)
    if ($actual.Count -ne $expected.Count) { throw 'Release bundle asset count differs' }
    $hashes = @{}
    foreach ($file in $actual) {
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $file.Name -cnotin $expected) { throw 'Unexpected release bundle entry' }
        $hashes[$file.Name] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    # Names and roles are fixed constants; the only free text is strictly validated Version.
    $lines = @('@{', '    Schema = 1', "    Product = 'org.einsatzarchiv'",
        "    ParentRole = 'org.einsatzarchiv.cli'", "    HelperRole = 'org.einsatzarchiv.operator.native'",
        "    Version = '$Version'", "    Architecture = '$Architecture'", '    Assets = @{')
    foreach ($name in $expected) { $lines += "        '$name' = '$($hashes[$name])'" }
    $lines += @('    }', '}')
    return ($lines -join "`r`n") + "`r`n"
}

function Assert-EaReleaseManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][Collections.IDictionary]$Manifest,
        [Parameter(Mandatory)][ValidateSet('win-x64','win-arm64', IgnoreCase=$false)][string]$Architecture,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][Collections.IDictionary]$Hashes)
    $keys = @('Schema','Product','ParentRole','HelperRole','Version','Architecture','Assets')
    foreach ($key in @('Product','ParentRole','HelperRole','Version','Architecture')) {
        if ($Manifest[$key] -isnot [string]) { throw 'Literal release text fields required' }
    }
    if ($Manifest.Count -ne 7 -or @($Manifest.Keys | Where-Object { $_ -cnotin $keys }).Count -ne 0 -or
        ($Manifest.Schema -isnot [int] -and $Manifest.Schema -isnot [long]) -or $Manifest.Schema -ne 1 -or
        $Manifest.Product -cne 'org.einsatzarchiv' -or $Manifest.ParentRole -cne 'org.einsatzarchiv.cli' -or
        $Manifest.HelperRole -cne 'org.einsatzarchiv.operator.native' -or $Manifest.Version -cne $Version -or
        $Manifest.Architecture -cne $Architecture -or $Manifest.Assets -isnot [Collections.IDictionary]) {
        throw 'Invalid closed release manifest'
    }
    $assets = @(Get-EaReleaseAssets)
    if ($Manifest.Assets.Count -ne 9 -or $Hashes.Count -ne 9 -or
        @($Manifest.Assets.Keys | Where-Object { $_ -cnotin $assets }).Count -ne 0 -or
        @($Hashes.Keys | Where-Object { $_ -cnotin $assets }).Count -ne 0) { throw 'Invalid release asset inventory' }
    foreach ($name in $assets) {
        $hash = $Manifest.Assets[$name]
        if ($hash -isnot [string] -or $hash -cnotmatch '\A[0-9a-f]{64}\z' -or $Hashes[$name] -cne $hash) {
            throw 'Release asset hash mismatch'
        }
    }
}

function Read-EaDataBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if ($Bytes.Length -gt 65536) { throw 'Manifest too large' }
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes).TrimStart([char]0xfeff)
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0 -or $null -ne $ast.ParamBlock -or $null -ne $ast.BeginBlock -or
        $null -ne $ast.ProcessBlock -or $null -ne $ast.DynamicParamBlock -or $null -eq $ast.EndBlock -or
        $ast.EndBlock.Statements.Count -ne 1) { throw 'Restricted manifest required' }
    $statement = $ast.EndBlock.Statements[0]
    if ($statement -isnot [Management.Automation.Language.PipelineAst] -or $statement.PipelineElements.Count -ne 1) { throw 'Restricted manifest required' }
    $element = $statement.PipelineElements[0]
    if ($element -isnot [Management.Automation.Language.CommandExpressionAst] -or $element.Redirections.Count -ne 0 -or
        $element.Expression -isnot [Management.Automation.Language.HashtableAst]) { throw 'Literal manifest required' }
    # SafeGetValue interprets constants; it does not execute PowerShell commands.
    return $element.Expression.SafeGetValue()
}

function Get-EaPeMachine {
    [CmdletBinding()]
    param([Parameter(Mandatory)][IO.Stream]$Stream)
    $reader = [IO.BinaryReader]::new($Stream, [Text.Encoding]::UTF8, $true)
    try {
        $Stream.Position = 0
        if ($Stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw 'DOS header required' }
        $Stream.Position = 0x3c; $offset = $reader.ReadUInt32()
        if ($offset -gt $Stream.Length - 6) { throw 'PE offset invalid' }
        $Stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550) { throw 'PE header required' }
        return $reader.ReadUInt16()
    } finally { $reader.Dispose(); $Stream.Position = 0 }
}

function Assert-EaAclPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Owner, [bool]$DaclPresent,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rules, [switch]$VolumeRoot)
    $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($Owner -notin $trusted -or -not $DaclPresent) { throw 'Protected owner and DACL required' }
    [long]$write = 0x500D0156
    if ($VolumeRoot) { $write = $write -band (-bnot 6) }
    foreach ($rule in $Rules) {
        if ($rule.Allow -and -not $rule.InheritOnly -and ([long]$rule.Rights -band $write) -ne 0 -and $rule.Sid -notin $trusted) {
            throw 'Unprivileged installation write permission'
        }
    }
}

Export-ModuleMember -Function Get-EaReleaseAssets, New-EaReleaseManifest, Assert-EaReleaseManifest, Read-EaDataBytes, Get-EaPeMachine, Assert-EaAclPolicy
