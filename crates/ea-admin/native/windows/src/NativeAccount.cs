using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Ea.NativeOperator;

internal sealed class NativeAccount : IDisposable
{
    internal SafeAccessTokenHandle Token { get; }
    internal byte[] Sid { get; }
    internal byte[] Authority => Sid[2..8];
    internal uint[] Subauthorities => Enumerable.Range(0, Sid[1]).Select(i => BinaryPrimitives.ReadUInt32LittleEndian(Sid.AsSpan(8 + 4 * i, 4))).ToArray();
    internal uint Session { get; }
    internal SecurityIdentifier SecurityId => new(Sid, 0);
    internal string LocalAppData { get; }
    internal NativeAccount()
    {
        if (Win32.OpenThreadToken(Win32.GetCurrentThread(), Win32.TokenQuery, true, out var impersonation))
        { impersonation.Dispose(); throw new Failure("account-unavailable"); }
        int threadTokenError = Marshal.GetLastWin32Error();
        impersonation.Dispose();
        if (threadTokenError != 1008) throw new Failure("account-unavailable");
        if (!Win32.OpenProcessToken(Win32.GetCurrentProcess(), Win32.KnownFolderTokenAccess, out var token)) throw new Failure("account-unavailable");
        Token = token;
        try
        {
            Sid = ReadSid(Token);
            Session = ReadNumber(Token, 12); // TokenSessionId; never a caller-provided identity.
            if (Session == 0 || ReadNumber(Token, 20) != 0) throw new Failure("account-unavailable"); // TokenElevation
            if (!Win32.GetProfileType(out var profile) || profile != 0) throw new Failure("nonroaming-profile-required");
            var localFolder = new Guid("F1B32785-6FBA-4FCF-9D55-7B8E7F157091");
            // The API owns an output allocation even on failure; always free it.
            int folderResult = Win32.SHGetKnownFolderPath(in localFolder, 0, Token, out var path);
            try
            {
                if (folderResult != 0) throw new Failure("account-unavailable");
                LocalAppData = Marshal.PtrToStringUni(path) ?? throw new Failure("account-unavailable");
            }
            finally { Marshal.FreeCoTaskMem(path); }
            if (!Path.IsPathFullyQualified(LocalAppData) || Win32.GetDriveType(Path.GetPathRoot(LocalAppData)!) != 3) throw new Failure("nonroaming-profile-required");
        }
        catch { Token.Dispose(); throw; }
    }
    internal static byte[] ReadSid(SafeAccessTokenHandle token)
    {
        Win32.GetTokenInformation(token, 1, 0, 0, out var required);
        if (required is < 8 or > 4096) throw new Failure("account-unavailable");
        var buffer = Marshal.AllocHGlobal((int)required);
        try
        {
            if (!Win32.GetTokenInformation(token, 1, buffer, required, out var returned) || returned > required) throw new Failure("account-unavailable");
            var sid = Marshal.ReadIntPtr(buffer);
            if (sid < buffer || sid + 8 > buffer + (int)required || !Win32.IsValidSid(sid)) throw new Failure("account-unavailable");
            var length = Win32.GetLengthSid(sid);
            if (length is < 8 or > 68 || sid + (int)length > buffer + (int)required) throw new Failure("account-unavailable");
            var bytes = new byte[length];
            Marshal.Copy(sid, bytes, 0, bytes.Length);
            if (bytes[0] != 1 || bytes[1] > 15 || bytes.Length != 8 + 4 * bytes[1]) throw new Failure("account-unavailable");
            return bytes;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    private static uint ReadNumber(SafeAccessTokenHandle token, int type)
    {
        var ptr = Marshal.AllocHGlobal(4);
        try
        {
            if (!Win32.GetTokenInformation(token, type, ptr, 4, out var size) || size != 4) throw new Failure("account-unavailable");
            return unchecked((uint)Marshal.ReadInt32(ptr));
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }
    internal bool IsInteractiveAccount()
    {
        var shell = Win32.GetShellWindow();
        if (shell == 0 || Win32.GetWindowThreadProcessId(shell, out var pid) == 0) return false;
        using var process = Win32.OpenProcess(0x1000, false, pid);
        if (process.IsInvalid || !Win32.OpenProcessToken(process.DangerousGetHandle(), Win32.TokenQuery, out var token)) return false;
        using (token) return Sid.SequenceEqual(ReadSid(token)) && Session == ReadNumber(token, 12);
    }
    internal bool MatchesToken(SafeAccessTokenHandle token) =>
        Sid.SequenceEqual(ReadSid(token)) && Session == ReadNumber(token, 12);
    internal void Recheck()
    {
        using var current = new NativeAccount();
        if (Session != current.Session || !CryptographicOperations.FixedTimeEquals(Sid, current.Sid) || LocalAppData != current.LocalAppData)
            throw new Failure("account-changed");
    }
    public void Dispose() => Token.Dispose();
}
