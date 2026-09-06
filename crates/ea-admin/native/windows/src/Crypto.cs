using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Ea.NativeOperator;

internal static class Crypto
{
    // Import defaults to KeyExportPolicies.None; no private-key export API is used.
    internal static byte[] PublicKey(ReadOnlySpan<byte> seed)
    {
        using var key = Key.Import(SignatureAlgorithm.Ed25519, seed, KeyBlobFormat.RawPrivateKey);
        return key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }
    internal static byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> data)
    {
        using var key = Key.Import(SignatureAlgorithm.Ed25519, seed, KeyBlobFormat.RawPrivateKey);
        return SignatureAlgorithm.Ed25519.Sign(key, data);
    }
    internal static byte[] Context(byte[] installationId, string slot, string kind, byte[]? publicKey)
        => Encoding.ASCII.GetBytes("EINSATZARCHIV-WINDOWS-SLOT-v1\0" + Hex.Encode(installationId) + "\0" + slot + "\0" + kind + "\0" + (publicKey == null ? "" : Hex.Encode(publicKey)));

    internal static byte[] Seal(byte[] secretMarkerKey, ReadOnlySpan<byte> plaintext, byte[] context)
    {
        var result = new byte[12 + 16 + plaintext.Length];
        RandomNumberGenerator.Fill(result.AsSpan(0, 12));
        using var aes = new AesGcm(secretMarkerKey, 16);
        aes.Encrypt(result.AsSpan(0, 12), plaintext, result.AsSpan(28), result.AsSpan(12, 16), context);
        return result;
    }
    internal static byte[] Open(byte[] secretMarkerKey, byte[] envelope, byte[] context)
    {
        if (envelope.Length != 60) throw new CryptographicException();
        var clear = new byte[32];
        try
        {
            using var aes = new AesGcm(secretMarkerKey, 16);
            aes.Decrypt(envelope.AsSpan(0, 12), envelope.AsSpan(28), envelope.AsSpan(12, 16), clear, context);
            return clear;
        }
        catch { CryptographicOperations.ZeroMemory(clear); throw; }
    }
}
