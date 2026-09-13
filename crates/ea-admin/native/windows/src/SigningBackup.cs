using System.Security.Cryptography;
namespace Ea.NativeOperator;

// Private post-authorization composition, shared by native dispatch and portable
// fixed-key tests. Its result is owned and cleared by provider/program, never JSON.
internal static class SigningBackup
{
    internal static byte[] Frame(Request request, ReadOnlySpan<byte> actualInstallation,
        ReadOnlySpan<byte> storedPublic, ReadOnlySpan<byte> seed)
    {
        request.RequireSigningBackup();
        if (actualInstallation.Length != 32 || !actualInstallation.SequenceEqual(Hex.Decode(request.InstallationId!)))
            throw new Failure("installation-changed");
        if (seed.Length != 32 || storedPublic.Length != 32 || !storedPublic.SequenceEqual(request.ExpectedPublicKey))
            throw new Failure("key-invalid");
        var actual = Crypto.PublicKey(seed);
        if (!actual.AsSpan().SequenceEqual(storedPublic)) throw new Failure("key-invalid");
        var frame = new byte[106];
        try {
            "EABKSEED"u8.CopyTo(frame); frame[8] = 1; frame[9] = request.Slot == "admin-signing" ? (byte)1 : (byte)2;
            actualInstallation.CopyTo(frame.AsSpan(10, 32)); actual.CopyTo(frame, 42); seed.CopyTo(frame.AsSpan(74, 32));
            return frame;
        } catch { CryptographicOperations.ZeroMemory(frame); throw; }
    }
}
