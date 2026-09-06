using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Ea.NativeOperator;

internal sealed record StoredSlot(string Kind, byte[]? PublicKey, byte[] Ciphertext);

internal sealed class CredentialStore(Installation installation)
{
    // Persist neither the public ID nor the wrapping key a second time: native
    // credential names contain a domain-separated, key-derived namespace tag.
    private string Target(string slot) => "Einsatzarchiv/NativeOperator/v1/" + Hex.Encode(HMACSHA256.HashData(
        installation.WrappingKey, Encoding.ASCII.GetBytes("EINSATZARCHIV-WINDOWS-NAMESPACE-v1\0" + installation.IdHex))) + "/" + slot;
    private byte[] Context(string slot, string kind, byte[]? publicKey) => Crypto.Context(installation.Id, slot, kind, publicKey);
    private string Tag(string slot, string kind, byte[]? publicKey, byte[] ciphertext)
    {
        var context = Context(slot, kind, publicKey);
        var metadataKey = HMACSHA256.HashData(installation.WrappingKey, "EINSATZARCHIV-WINDOWS-METADATA-v1"u8);
        try { return Hex.Encode(HMACSHA256.HashData(metadataKey, context.Concat(ciphertext).ToArray())); }
        finally { CryptographicOperations.ZeroMemory(metadataKey); }
    }
    internal StoredSlot? ReadMetadata(string slot)
    {
        if (!Win32.CredRead(Target(slot), 1, 0, out var pointer))
        {
            if (Marshal.GetLastWin32Error() == 1168) return null;
            throw new Failure("store-unavailable");
        }
        try
        {
            var credential = Marshal.PtrToStructure<Win32.Credential>(pointer);
            // CRED_PERSIST_LOCAL_MACHINE = user credential persists only on this
            // computer. It DOES NOT select machine-scope DPAPI protection.
            if (credential.Type != 1 || credential.Persist != 2 || credential.TargetName != Target(slot) || credential.CredentialBlobSize is < 32 or > 2560 || credential.CredentialBlob == 0 || credential.Comment == null) throw new Failure("key-invalid");
            var parts = credential.Comment.Split(':');
            if (parts.Length != 4 || parts[0] != "v1" || parts[1] is not ("ed25519" or "secret32") || Request.IsSecret(slot) != (parts[1] == "secret32")) throw new Failure("key-invalid");
            byte[]? publicKey = parts[1] == "ed25519" ? Hex.Decode(parts[2]) : null;
            if ((publicKey != null && publicKey.Length != 32) || (publicKey == null && parts[2] != "")) throw new Failure("key-invalid");
            var ciphertext = new byte[credential.CredentialBlobSize];
            Marshal.Copy(credential.CredentialBlob, ciphertext, 0, ciphertext.Length);
            if (parts[3].Length != 64 || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(parts[3]), Encoding.ASCII.GetBytes(Tag(slot, parts[1], publicKey, ciphertext)))) throw new Failure("key-invalid");
            // Metadata queries never CryptUnprotectData or decrypt a private slot.
            return new StoredSlot(parts[1], publicKey, ciphertext);
        }
        finally { Win32.CredFree(pointer); }
    }
    internal unsafe void Put(string slot, string kind, byte[] secret, byte[]? publicKey, bool replace)
    {
        if (secret.Length != 32) throw new Failure("key-invalid");
        if (!replace && ReadMetadata(slot) != null) throw new Failure("key-exists");
        var context = Context(slot, kind, publicKey);
        var envelope = Crypto.Seal(installation.WrappingKey, secret, context);
        var ciphertext = Dpapi.Protect(envelope, context);
        CryptographicOperations.ZeroMemory(envelope);
        fixed (byte* bytes = ciphertext)
        {
            var credential = new Win32.Credential {
                Type = 1, TargetName = Target(slot), Persist = 2,
                Comment = "v1:" + kind + ":" + (publicKey == null ? "" : Hex.Encode(publicKey)) + ":" + Tag(slot, kind, publicKey, ciphertext),
                CredentialBlob = (nint)bytes, CredentialBlobSize = (uint)ciphertext.Length
            };
            if (!Win32.CredWrite(ref credential, 0)) throw new Failure("store-unavailable");
        }
        var verified = ReadMetadata(slot);
        if (verified == null || !verified.Ciphertext.SequenceEqual(ciphertext)) throw new Failure("store-unavailable");
    }
    internal byte[] ReadSecret(string slot, StoredSlot stored)
    {
        var context = Context(slot, stored.Kind, stored.PublicKey);
        var envelope = Dpapi.Unprotect(stored.Ciphertext, context);
        try { return Crypto.Open(installation.WrappingKey, envelope, context); }
        finally { CryptographicOperations.ZeroMemory(envelope); }
    }
    internal void Delete(string slot)
    {
        if (!Win32.CredDelete(Target(slot), 1, 0) && Marshal.GetLastWin32Error() != 1168) throw new Failure("store-unavailable");
    }
}
