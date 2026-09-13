using System.Text;
using System.Security.Cryptography;
using System.Reflection;
using Ea.NativeOperator;

internal static class SigningBackupTests
{
    internal static void Run(Action<bool,string> check)
    {
        var seed = Enumerable.Repeat((byte)0x47,32).ToArray();
        var key = Crypto.PublicKey(seed);
        var installation = new byte[32];
        Request Valid() => Request.Parse(Encoding.UTF8.GetBytes($"{{\"op\":\"backup-signing-seed\",\"slot\":\"admin-signing\",\"installation_id\":\"{Hex.Encode(installation)}\",\"expected_public_key\":\"{Hex.Encode(key)}\",\"presence\":true}}"));
        void Denied(string code, Action body) {
            try { body(); throw new Exception("backup should refuse"); }
            catch (Failure f) { check(f.Code == code, "closed backup refusal"); }
        }
        var bounded = Encoding.UTF8.GetBytes($"{{\"op\":\"backup-signing-seed\",\"slot\":\"admin-signing\",\"installation_id\":\"{Hex.Encode(installation)}\",\"expected_public_key\":\"{Hex.Encode(key)}\",\"presence\":true}}");
        var exact = Enumerable.Repeat((byte)' ',512).ToArray(); bounded.CopyTo(exact,0);
        using (var atLimit = Request.Parse(exact)) check(atLimit.Op == "backup-signing-seed", "exact 512-byte admission");
        using var valid = Valid();
        var other = new byte[32]; other[0] = 1;
        Denied("installation-changed", () => SigningBackup.Frame(valid, other, key, seed));
        Denied("key-invalid", () => SigningBackup.Frame(valid, installation, other, seed));
        Denied("key-invalid", () => SigningBackup.Frame(valid, installation, key, new byte[31]));
        // Directly constructed invalid object cannot bypass the shared provider validator.
        foreach (var slot in new[] { "operator-instance", "writer-signing", "database-key", "draft-key", "other" }) {
            using var forged = Valid();
            typeof(Request).GetProperty("Slot", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(forged, slot);
            Denied("invalid-request", forged.RequireSigningBackup);
            Denied("invalid-request", () => SigningBackup.Frame(forged, installation, key, seed));
        }
        using (var noPresence = Valid()) {
            typeof(Request).GetProperty("Presence", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(noPresence, false);
            Denied("presence-required", noPresence.RequireSigningBackup);
        }
        using var closed = new MemoryStream(); closed.Dispose();
        var frame = SigningBackup.Frame(valid, installation, key, seed);
        try { Transport.WriteSigningBackup(closed, frame); throw new Exception("closed writer accepted"); }
        catch (ObjectDisposedException) { check(frame.All(b => b == 0), "failed output clears frame"); }
        var malformed = Enumerable.Repeat((byte)0x47,105).ToArray();
        Denied("native-failed", () => Transport.WriteSigningBackup(Stream.Null, malformed));
        check(malformed.All(b => b == 0), "invalid frame size clears owned output");
        CryptographicOperations.ZeroMemory(seed);
    }
}
