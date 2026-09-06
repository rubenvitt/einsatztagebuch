using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace Ea.NativeOperator;

internal sealed class Installation : IDisposable
{
    private const string BackupBase = @"SYSTEM\CurrentControlSet\Control\BackupRestore";
    private const string PolicyValue = "Einsatzarchiv.NativeOperator.v1";
    private readonly NativeAccount account;
    private readonly string directory;
    private readonly string markerPath;
    private readonly FileStream gate;
    private FileStream? marker;
    private byte[] markerHash = [];
    private readonly byte[] environment;
    internal byte[] Id { get; private set; } = [];
    internal byte[] WrappingKey { get; private set; } = [];
    internal string IdHex => Hex.Encode(Id);

    internal Installation(NativeAccount account, bool initialize)
    {
        this.account = account;
        directory = Path.Combine(account.LocalAppData, "Einsatzarchiv", "NativeOperator-v1");
        markerPath = Path.Combine(directory, "marker.bin");
        if (!initialize && !File.Exists(markerPath)) throw new Failure("installation-missing");
        RequirePolicy(directory);
        environment = EnvironmentBinding(account);
        RequireNoReparse(account.LocalAppData);
        if (!Directory.Exists(directory))
        {
            if (!initialize) throw new Failure("installation-missing");
            var parent = Path.GetDirectoryName(directory)!;
            RequireNoReparse(parent);
            Directory.CreateDirectory(parent);
            FileSystemAclExtensions.CreateDirectory(Security(), directory);
        }
        RequireNoReparse(directory);
        RequireAcl(new DirectoryInfo(directory).GetAccessControl(), account);
        // Serializes helper operations in this account. FileShare.None plus the
        // marker's held handle prevents replacement by cooperating invocations.
        var gatePath = Path.Combine(directory, "operation.lock");
        RequireNoReparse(gatePath);
        try { gate = new FileStream(gatePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { throw new Failure("installation-busy"); }
    }
    private DirectorySecurity Security()
    {
        var security = new DirectorySecurity();
        security.SetOwner(account.SecurityId);
        security.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { account.SecurityId, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }
    private static void RequireAcl(FileSystemSecurity security, NativeAccount account)
    {
        if (!account.SecurityId.Equals(security.GetOwner(typeof(SecurityIdentifier)))) throw new Failure("installation-invalid");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        if (security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Count == 0) throw new Failure("installation-invalid");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !rule.IdentityReference.Equals(account.SecurityId) && !rule.IdentityReference.Equals(system)) throw new Failure("installation-invalid");
    }
    private static void RequireNoReparse(string path)
    {
        for (string? current = path; current != null; current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new Failure("installation-invalid");
    }
    private static void RequirePolicy(string directory)
    {
        // These are real Windows Backup/VSS facilities, set by the elevated
        // installer, not an archive attribute or a boolean in our own config.
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        foreach (var facility in new[] { "FilesNotToBackup", "FilesNotToSnapshot" })
        {
            using var key = hklm.OpenSubKey(BackupBase + "\\" + facility, false);
            if (key == null || key.GetValue(PolicyValue, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string[] paths ||
                key.GetValueKind(PolicyValue) != RegistryValueKind.MultiString ||
                !paths.Contains(directory + @"\* /s", StringComparer.OrdinalIgnoreCase)) throw new Failure("backup-policy-required");
        }
    }
    private static byte[] EnvironmentBinding(NativeAccount account)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var crypto = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", false);
        using var restore = hklm.OpenSubKey(BackupBase + @"\SystemStateRestore", false);
        if (crypto?.GetValue("MachineGuid") is not string machine || !Guid.TryParse(machine, out _)) throw new Failure("installation-invalid");
        var restoreValue = restore?.GetValue("LastRestoreId", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (restoreValue is not null and not string) throw new Failure("installation-invalid");
        var lastRestore = restoreValue as string;
        if (lastRestore?.Length > 1024) throw new Failure("installation-invalid");
        return SHA256.HashData(Encoding.UTF8.GetBytes("EINSATZARCHIV-WINDOWS-MARKER-v1\0" + Hex.Encode(account.Sid) + "\0" + machine + "\0" + (lastRestore == null ? "absent" : "present:" + lastRestore)));
    }
    internal bool Load()
    {
        if (!File.Exists(markerPath)) return false;
        RequireNoReparse(markerPath);
        marker = new FileStream(markerPath, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
        RequireAcl(marker.GetAccessControl(), account);
        var protectedBytes = ReadMarker(marker);
        byte[]? clear = null;
        try
        {
            clear = Dpapi.Unprotect(protectedBytes, environment);
            // Version + independent public id + secret wrapping key. Both random
            // values are ONLY persisted together inside this user-DPAPI blob.
            if (clear.Length != 65 || clear[0] != 1) throw new Failure("installation-invalid");
            Id = clear[1..33]; WrappingKey = clear[33..65];
            if (CryptographicOperations.FixedTimeEquals(Id, WrappingKey)) throw new Failure("installation-invalid");
            markerHash = SHA256.HashData(protectedBytes);
            return true;
        }
        catch { throw new Failure("installation-invalid"); }
        finally { if (clear != null) CryptographicOperations.ZeroMemory(clear); }
    }
    internal void Create()
    {
        RequirePolicy(directory);
        if (File.Exists(markerPath)) throw new Failure("installation-changed");
        var clear = new byte[65];
        clear[0] = 1;
        // Independent CSPRNG calls; the public id is never an encryption key.
        Id = RandomNumberGenerator.GetBytes(32);
        WrappingKey = RandomNumberGenerator.GetBytes(32);
        Id.CopyTo(clear, 1); WrappingKey.CopyTo(clear, 33);
        try
        {
            var encrypted = Dpapi.Protect(clear, environment);
            marker = new FileStream(markerPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.WriteThrough);
            marker.Write(encrypted); marker.Flush(true);
            RequireAcl(marker.GetAccessControl(), account);
            markerHash = SHA256.HashData(encrypted);
            Recheck();
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    private static byte[] ReadMarker(FileStream? marker)
    {
        if (marker == null || marker.Length is < 32 or > 8192) throw new Failure("installation-invalid");
        marker.Position = 0;
        var bytes = new byte[marker.Length];
        marker.ReadExactly(bytes);
        return bytes;
    }
    internal void Recheck()
        => RecheckMarker(account, directory, markerPath, environment, markerHash, marker);
    private static void RecheckMarker(NativeAccount account, string directory, string markerPath, byte[] environment, byte[] markerHash, FileStream? marker)
    {
        RequirePolicy(directory); RequireNoReparse(directory); RequireNoReparse(markerPath);
        RequireAcl(new DirectoryInfo(directory).GetAccessControl(), account);
        if (marker == null) throw new Failure("installation-missing");
        RequireAcl(marker.GetAccessControl(), account);
        if (!CryptographicOperations.FixedTimeEquals(environment, EnvironmentBinding(account)) || !CryptographicOperations.FixedTimeEquals(markerHash, SHA256.HashData(ReadMarker(marker)))) throw new Failure("installation-changed");
        account.Recheck();
    }
    internal Observation Observe()
    {
        Recheck();
        var observation = new Observation(account, directory, markerPath, environment, markerHash);
        try { observation.Recheck(); return observation; }
        catch { observation.Dispose(); throw; }
    }
    // Contains only hashes, native account context and filesystem subscriptions.
    // The watch disposes the originating Installation (and wipes its wrapping
    // key) before ready. Normal operations keep their exclusive operation gate
    // while permitting these short-lived, read-only protected-blob observations.
    internal sealed class Observation : IDisposable
    {
        private readonly NativeAccount account;
        private readonly string directory, markerPath;
        private readonly byte[] environment, markerHash;
        private readonly FileSystemWatcher markerEvents, directoryEvents;
        private int changed;
        internal Observation(NativeAccount account, string directory, string markerPath, byte[] environment, byte[] markerHash)
        {
            this.account = account; this.directory = directory; this.markerPath = markerPath;
            this.environment = environment.ToArray(); this.markerHash = markerHash.ToArray();
            markerEvents = new FileSystemWatcher(directory, Path.GetFileName(markerPath));
            directoryEvents = new FileSystemWatcher(Path.GetDirectoryName(directory)!, Path.GetFileName(directory));
            try
            {
                foreach (var watcher in new[] { markerEvents, directoryEvents })
                {
                    watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite |
                        NotifyFilters.Size | NotifyFilters.Security | NotifyFilters.CreationTime;
                    watcher.Changed += Changed; watcher.Deleted += Changed; watcher.Created += Changed;
                    watcher.Renamed += Renamed; watcher.Error += Error;
                    watcher.EnableRaisingEvents = true;
                }
            }
            catch { Dispose(); throw; }
        }
        private void Changed(object sender, FileSystemEventArgs args) => Interlocked.Exchange(ref changed, 1);
        private void Renamed(object sender, RenamedEventArgs args) => Interlocked.Exchange(ref changed, 1);
        private void Error(object sender, ErrorEventArgs args) => Interlocked.Exchange(ref changed, 1);
        internal void Recheck()
        {
            if (Volatile.Read(ref changed) != 0) throw new Failure("installation-changed");
            RequireNoReparse(markerPath);
            using var current = new FileStream(markerPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            RecheckMarker(account, directory, markerPath, environment, markerHash, current);
            if (Volatile.Read(ref changed) != 0) throw new Failure("installation-changed");
        }
        public void Dispose() { markerEvents.Dispose(); directoryEvents.Dispose(); }
    }
    internal void RequireExpected(string? expected)
    { if (expected != null && !string.Equals(expected, IdHex, StringComparison.Ordinal)) throw new Failure("installation-changed"); }
    internal void Reset()
    {
        Recheck();
        // Keep the operation gate. Never enumerate/delete old Credential slots.
        // Destroy contents before unlinking; logical deletion is not SSD erasure.
        marker!.Position = 0; marker.Write(new byte[marker.Length]); marker.Flush(true);
        marker.Dispose(); marker = null;
        File.Delete(markerPath);
    }
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(WrappingKey);
        marker?.Dispose(); gate.Dispose();
    }
}
