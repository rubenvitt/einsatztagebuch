using System.Security.Principal;
using Ea.NativeOperator;

if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000)) {
    Console.WriteLine("NOT RUN: requires a real Windows 11 unelevated local account.");
    return 2;
}
try {
    // Executes the unmodified production constructor, including OpenProcessToken
    // and SHGetKnownFolderPath. No substitute known-folder result or key store.
    using var account = new NativeAccount();
    using var identity = WindowsIdentity.GetCurrent();
    var sid = new byte[identity.User!.BinaryLength];
    identity.User.GetBinaryForm(sid, 0);
    if (!sid.SequenceEqual(account.Sid)) throw new Exception();
    if (!string.Equals(account.LocalAppData,
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        StringComparison.OrdinalIgnoreCase)) throw new Exception();
    account.Recheck();
    Console.WriteLine("PASS: real TokenUser / explicit-token Known Folder / current account recheck; no credentials or marker mutated.");
    return 0;
} catch {
    Console.WriteLine("FAIL: actual Windows account/Known Folder regression. No account/path or native error details emitted.");
    return 1;
}
