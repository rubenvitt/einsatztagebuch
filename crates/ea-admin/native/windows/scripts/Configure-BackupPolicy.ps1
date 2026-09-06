# Installer action only. Never invoked by the helper or by protocol tests.
# Run elevated on the TARGET Windows machine, for a reviewed account-local path.
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$MarkerDirectory)
$ErrorActionPreference = 'Stop'
if (-not [OperatingSystem]::IsWindows()) { throw 'Windows required' }
$directory = [IO.Path]::GetFullPath($MarkerDirectory).TrimEnd('\')
if ($directory -notmatch '^[A-Za-z]:\\' -or $directory -match '[*?\r\n%]' -or
    -not $directory.EndsWith('\Einsatzarchiv\NativeOperator-v1', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Use the exact account LocalAppData\Einsatzarchiv\NativeOperator-v1 path'
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator installer required'
}
$hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
try {
    foreach ($facility in @('FilesNotToBackup', 'FilesNotToSnapshot')) {
        $path = "SYSTEM\CurrentControlSet\Control\BackupRestore\$facility"
        if ($PSCmdlet.ShouldProcess($path, 'Add and verify application marker exclusion')) {
            $key = $hklm.CreateSubKey($path)
            try {
                $name = 'Einsatzarchiv.NativeOperator.v1'
                $existing = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if ($null -ne $existing -and $key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::MultiString) { throw 'Existing policy has incorrect type' }
                [string[]]$values = @(@($existing) | Where-Object { $null -ne $_ }) + @("$directory\* /s")
                [string[]]$values = @($values | Select-Object -Unique)
                $key.SetValue($name, $values, [Microsoft.Win32.RegistryValueKind]::MultiString)
                $key.Flush()
                if ($key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::MultiString -or "$directory\* /s" -notin $key.GetValue($name)) { throw 'Policy readback failed' }
            } finally { $key.Dispose() }
        }
    }
} finally { $hklm.Dispose() }
# This checks configured facilities, not a completed backup/restore. See README.
