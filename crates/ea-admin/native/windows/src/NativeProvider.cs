using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Ea.NativeOperator;

internal static class NativeProvider
{
    internal static void RequireParentPipes()
    {
        if (Win32.NtQueryInformationProcess(Win32.GetCurrentProcess(), 0, out var processInfo, Marshal.SizeOf<Win32.ProcessBasicInformation>(), out _) != 0) throw new Failure("protected-pipe-required");
        var parentId = checked((uint)processInfo.ParentPid);
        using var parent = Win32.OpenProcess(0x1000, false, parentId);
        if (parent.IsInvalid || !Win32.OpenProcessToken(parent.DangerousGetHandle(), Win32.TokenQuery, out var parentToken)) throw new Failure("protected-pipe-required");
        using (parentToken)
        using (var account = new NativeAccount())
            if (!account.Sid.SequenceEqual(NativeAccount.ReadSid(parentToken))) throw new Failure("protected-pipe-required");
        foreach (int std in new[] { -10, -11 })
        {
            var handle = Win32.GetStdHandle(std);
            if (Win32.GetFileType(handle) != 3 || !Win32.GetNamedPipeInfo(handle, out var flags, out _, out _, out _) || (flags & 4) != 0 ||
                !Win32.GetNamedPipeClientProcessId(handle, out var client) || !Win32.GetNamedPipeServerProcessId(handle, out var server) ||
                (client != parentId && client != Environment.ProcessId) || (server != parentId && server != Environment.ProcessId)) throw new Failure("protected-pipe-required");
        }
    }

    internal static byte[] Execute(Request request)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) || !Environment.Is64BitProcess) throw new Failure("platform-unavailable");
        RequireParentPipes();
        using var account = new NativeAccount();
        using var session = new SessionWindow(account);
        using var installation = new Installation(account, request.Op == "initialize");
        bool present = installation.Load();
        if (!present)
        {
            if (request.Op != "initialize") throw new Failure("installation-missing");
            // A pinned parent must reopen provisioning explicitly after loss.
            if (request.InstallationId != null) throw new Failure("installation-changed");
            session.RequireUnlocked();
            if (request.Presence) session.VerifyPresence();
            account.Recheck();
            installation.Create();
        }
        installation.RequireExpected(request.InstallationId);
        installation.Recheck();
        if (request.Presence && present) session.VerifyPresence();
        if (request.Op is "account" or "initialize")
        {
            bool locked = session.Locked();
            installation.Recheck();
            return JsonSerializer.SerializeToUtf8Bytes(new {
                ok = true, installation_id = installation.IdHex, platform = "windows",
                sid = Hex.Encode(account.Sid), identifier_authority = Hex.Encode(account.Authority),
                subauthorities = account.Subauthorities, locked
            });
        }
        session.RequireUnlocked();
        if (request.Op == "private-console-line")
        {
            using var line = new ConsoleLineBuffer(request.MaxBytes);
            PrivateConsoleLine.Read(request.Label!, request.MaxBytes, request.TimeoutMs, line,
                () => { installation.Recheck(); session.RequireUnlocked(); });
            // Read restores console mode before returning; never serialize a
            // partial line or one captured across an account/installation change.
            installation.Recheck(); session.RequireUnlocked(); RequireParentPipes();
            return Transport.LineReply(installation.IdHex, line.Line);
        }
        if (request.Op == "reset")
        {
            installation.Reset();
            account.Recheck(); session.RequireUnlocked();
            return JsonSerializer.SerializeToUtf8Bytes(new { ok = true, installation_id = installation.IdHex, reset = true });
        }
        var store = new CredentialStore(installation);
        var fields = new Dictionary<string, object?> { ["ok"] = true, ["installation_id"] = installation.IdHex };
        byte[]? secretOutput = null;
        try
        {
            string slot = request.Slot!;
            if (request.Op is "generate" or "wrap-secret")
            {
                var secret = request.Op == "generate" ? RandomNumberGenerator.GetBytes(32) : request.Data!.ToArray();
                try
                {
                    string kind = request.Op == "wrap-secret" ? "secret32" : request.Kind!;
                    byte[]? publicKey = kind == "ed25519" ? Crypto.PublicKey(secret) : null;
                    installation.Recheck(); session.RequireUnlocked();
                    store.Put(slot, kind, secret, publicKey, request.Replace);
                    if (request.Op == "generate") fields["public_key"] = publicKey == null ? null : Hex.Encode(publicKey);
                }
                finally { CryptographicOperations.ZeroMemory(secret); }
            }
            else
            {
                var stored = store.ReadMetadata(slot);
                if (stored != null && request.Kind != null && request.Kind != stored.Kind) throw new Failure("key-kind-mismatch");
                switch (request.Op)
                {
                    case "contains": fields["contains"] = stored != null; break;
                    case "public-key": fields["public_key"] = stored?.PublicKey == null ? null : Hex.Encode(stored.PublicKey); break;
                    case "delete": store.Delete(slot); break;
                    case "sign": case "unwrap-secret":
                        if (stored == null) throw new Failure("key-missing");
                        var secret = store.ReadSecret(slot, stored);
                        try
                        {
                            if (request.Op == "unwrap-secret") secretOutput = secret.ToArray();
                            else
                            {
                                if (stored.PublicKey == null || !Crypto.PublicKey(secret).SequenceEqual(stored.PublicKey)) throw new Failure("key-invalid");
                                fields["signature"] = Hex.Encode(Crypto.Sign(secret, request.Data!));
                            }
                        }
                        finally { CryptographicOperations.ZeroMemory(secret); }
                        break;
                    default: throw new Failure("invalid-request");
                }
            }
            // Lock/account/marker changes suppress signatures and plaintext, even
            // if the store mutation has already completed. Never auto-retry it.
            installation.Recheck(); session.RequireUnlocked();
            if (secretOutput == null) return JsonSerializer.SerializeToUtf8Bytes(fields);
            return Transport.SecretReply(installation.IdHex, secretOutput);
        }
        finally { if (secretOutput != null) CryptographicOperations.ZeroMemory(secretOutput); }
    }
}
