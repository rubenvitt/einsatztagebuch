Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This module is imported from authenticated bytes by the deployment entrypoints.
# Importing/compiling it alone never invokes a Windows API or changes the host.
function Initialize-EaReleaseNative {
    if ('Ea.Release.Native' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
namespace Ea.Release {
    public sealed class Pins : IDisposable {
        internal readonly List<SafeFileHandle> Handles = new List<SafeFileHandle>();
        public readonly List<string> Paths = new List<string>();
        public FileStream Stream { get; internal set; }
        public string Path { get; internal set; }
        public void Dispose() {
            if (Stream != null) Stream.Dispose();
            for (int i = Handles.Count - 1; i >= 0; --i) Handles[i].Dispose();
            Handles.Clear();
        }
    }
    public static class Native {
        [StructLayout(LayoutKind.Sequential)] struct Info {
            public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [StructLayout(LayoutKind.Sequential)] struct Attributes {
            public uint Length; public IntPtr Descriptor; public int Inherit;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern SafeFileHandle CreateFileW(string path, uint access, uint share, ref Attributes security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle file, out Info info);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool GetVolumeInformationW(string root, IntPtr volumeName, uint volumeSize, out uint serial, out uint maxComponent, out uint flags, IntPtr fileSystem, uint fileSystemSize);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool CreateDirectoryW(string path, ref Attributes security);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr descriptor, out uint size);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        static Exception Failure() { return new Win32Exception(Marshal.GetLastWin32Error()); }
        public static string FullPath(string path) {
            if (path == null || path.Length < 3 || !Char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\' || path.Substring(2).Contains(':'))
                throw new InvalidOperationException("Local absolute release path required");
            string result = System.IO.Path.GetFullPath(path);
            return result.Length == 3 ? result : result.TrimEnd('\\');
        }
        public static Pins Open(string path, bool file) {
            var pins = new Pins();
            try {
                string full = FullPath(path), root = System.IO.Path.GetPathRoot(full), current = root;
                uint serial, maxComponent, flags;
                if (new DriveInfo(root).DriveType != DriveType.Fixed ||
                    !GetVolumeInformationW(root,IntPtr.Zero,0,out serial,out maxComponent,out flags,IntPtr.Zero,0) || (flags & 8) == 0)
                    throw new InvalidOperationException("Local fixed volume with persistent ACLs required");
                var paths = new List<string> { root };
                if (full.Length > root.Length) foreach (string part in full.Substring(root.Length).Split('\\')) {
                    if (part.Length == 0 || part.EndsWith(".") || part.EndsWith(" ")) throw new InvalidOperationException("Noncanonical release path");
                    current = System.IO.Path.Combine(current, part); paths.Add(current);
                }
                for (int i = 0; i < paths.Count; ++i) {
                    bool lastFile = file && i == paths.Count - 1;
                    // Volume roots cannot be renamed; allow unrelated root writes.
                    // Every other component denies write/delete opens while held.
                    var handle = CreateFileW(paths[i], lastFile ? 0x80020080u : 0x20080u,
                        i == 0 ? 3u : 1u, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                    if (handle.IsInvalid) { handle.Dispose(); throw Failure(); }
                    pins.Handles.Add(handle); pins.Paths.Add(paths[i]);
                    Info info;
                    if (!GetFileInformationByHandle(handle, out info)) throw Failure();
                    if ((info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) == 0) != lastFile || (lastFile && info.Links != 1))
                        throw new InvalidOperationException("Regular single-link release tree required");
                    if (lastFile) pins.Stream = new FileStream(handle, FileAccess.Read);
                }
                pins.Path = full; return pins;
            } catch { pins.Dispose(); throw; }
        }
        static Attributes Security(bool directory) {
            string inherit = directory ? "OICI" : "";
            string sddl = "O:BAG:SYD:P(A;"+inherit+";FA;;;SY)(A;"+inherit+";FA;;;BA)(A;"+inherit+";0x1200a9;;;BU)";
            IntPtr descriptor; uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor, out size)) throw Failure();
            return new Attributes { Length=(uint)Marshal.SizeOf<Attributes>(), Descriptor=descriptor, Inherit=0 };
        }
        public static void CreateProtectedDirectory(string path) {
            var security = Security(true);
            try { if (!CreateDirectoryW(FullPath(path), ref security)) throw Failure(); }
            finally { LocalFree(security.Descriptor); }
        }
        public static void CopyNewProtectedFile(FileStream source, string path) {
            var security = Security(false);
            try {
                // CREATE_NEW and the final protected ACL are atomic; never overwrite.
                using (var handle = CreateFileW(FullPath(path), 0xC0000000, 0, ref security, 1, 0x00200000, IntPtr.Zero)) {
                    if (handle.IsInvalid) throw Failure();
                    using (var target = new FileStream(handle, FileAccess.ReadWrite)) {
                        source.Position = 0; source.CopyTo(target); target.Flush(true); source.Position = 0;
                    }
                }
            } finally { LocalFree(security.Descriptor); }
        }
    }
}
'@
}

function Assert-EaProtectedPins {
    param([Parameter(Mandatory)]$Pins)
    foreach ($path in $Pins.Paths) {
        $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $path
        $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
        $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
            @{Allow=($_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)
              InheritOnly=(($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
              Rights=[long]$_.FileSystemRights; Sid=$_.IdentityReference.Value}
        })
        Assert-EaAclPolicy -Owner $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -DaclPresent ($null -ne $raw.DiscretionaryAcl) -Rules $rules -VolumeRoot:($path -eq [IO.Path]::GetPathRoot($path))
    }
}

function Get-EaStreamHash {
    param([Parameter(Mandatory)][IO.Stream]$Stream)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $Stream.Position=0; return [Convert]::ToHexString($hash.ComputeHash($Stream)).ToLowerInvariant() }
    finally { $hash.Dispose(); $Stream.Position=0 }
}

function Assert-EaFileSigner {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][byte[]]$CertificateDer)
    # Caller holds the entire path and read/no-write/no-delete file handles.
    $signature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
        [Convert]::ToBase64String($signature.SignerCertificate.RawData) -cne [Convert]::ToBase64String($CertificateDer)) {
        throw 'Release signature or exact DER publisher mismatch'
    }
}

function Open-EaReleaseBundle {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Bundle,
        [Parameter(Mandatory)][ValidateSet('win-x64','win-arm64', IgnoreCase=$false)][string]$Architecture,
        [Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][byte[]]$CertificateDer,
        [switch]$RequireProtected)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Windows release verification required' }
    Initialize-EaReleaseNative
    $pins = [Collections.Generic.List[IDisposable]]::new(); $files=@{}
    try {
        $directory = [Ea.Release.Native]::Open($Bundle,$false); $pins.Add($directory)
        if ($RequireProtected) { Assert-EaProtectedPins $directory }
        $expected = @(Get-EaReleaseAssets) + @('ea-native-operator.release.psd1')
        $entries = @([IO.Directory]::GetFileSystemEntries($directory.Path))
        if ($entries.Count -ne 10) { throw 'Closed release bundle must contain ten files' }
        foreach ($path in $entries) {
            $name = [IO.Path]::GetFileName($path)
            if ($name -cnotin $expected -or $files.ContainsKey($name)) { throw 'Unexpected release entry' }
            $file = [Ea.Release.Native]::Open($path,$true); $pins.Add($file); $files[$name]=$file
            if ($file.Stream.Length -gt 268435456) { throw 'Release asset size limit' }
            if ($RequireProtected) { Assert-EaProtectedPins $file }
        }
        foreach ($name in @('einsatzarchiv.exe','ea-native-operator.exe','ea-native-operator.release.psd1')) {
            Assert-EaFileSigner $files[$name].Path $CertificateDer
        }
        $manifestStream = $files['ea-native-operator.release.psd1'].Stream
        if ($manifestStream.Length -gt 65536) { throw 'Release manifest size limit' }
        $bytes=[byte[]]::new([int]$manifestStream.Length); $manifestStream.ReadExactly($bytes,0,$bytes.Length); $manifestStream.Position=0
        $manifest=Read-EaDataBytes $bytes; $hashes=@{}
        foreach ($name in Get-EaReleaseAssets) { $hashes[$name]=Get-EaStreamHash $files[$name].Stream }
        Assert-EaReleaseManifest $manifest $Architecture $Version $hashes
        $machine=if ($Architecture -eq 'win-x64') { 0x8664 } else { 0xaa64 }
        foreach ($name in @('einsatzarchiv.exe','ea-native-operator.exe')) {
            if ((Get-EaPeMachine $files[$name].Stream) -ne $machine) { throw 'Release executable architecture mismatch' }
        }
        return [pscustomobject]@{Directory=$directory.Path; Pins=$pins; Files=$files; Manifest=$manifest}
    } catch { foreach ($pin in $pins) { $pin.Dispose() }; throw }
}

function Close-EaReleaseBundle {
    param([Parameter(Mandatory)]$Bundle)
    foreach ($pin in $Bundle.Pins) { $pin.Dispose() }
}

Export-ModuleMember -Function Initialize-EaReleaseNative, Assert-EaProtectedPins, Get-EaStreamHash, Assert-EaFileSigner, Open-EaReleaseBundle, Close-EaReleaseBundle
