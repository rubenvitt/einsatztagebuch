using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Ea.NativeOperator;

internal sealed class ParentLifetime : IDisposable
{
    private readonly SafeProcessHandle process;
    private readonly NativeAccount account;
    private readonly nint input = Win32.GetStdHandle(-10);
    private readonly nint output = Win32.GetStdHandle(-11);
    internal ParentLifetime(NativeAccount account)
    {
        this.account = account;
        if (Win32.NtQueryInformationProcess(Win32.GetCurrentProcess(), 0, out var info, Marshal.SizeOf<Win32.ProcessBasicInformation>(), out _) != 0)
            throw new Failure("protected-pipe-required");
        // A held kernel process handle observes the original parent's lifetime,
        // not a later process which happens to reuse its numeric PID.
        process = Win32.OpenProcess(0x00101000, false, checked((uint)info.ParentPid)); // SYNCHRONIZE | QUERY_LIMITED_INFORMATION
        if (process.IsInvalid) { process.Dispose(); throw new Failure("protected-pipe-required"); }
    }
    internal void Recheck()
    {
        if (Win32.WaitForSingleObject(process, 0) != 258 ||
            !Win32.OpenProcessToken(process.DangerousGetHandle(), Win32.TokenQuery, out var token)) throw new Failure("parent-disconnected");
        using (token) if (!account.MatchesToken(token)) throw new Failure("account-changed");
        _ = AvailableInput(); // EOF/broken pipe terminates; challenges follow ready
        RequireWritable(0);
    }
    internal uint AvailableInput()
    {
        if (!Win32.PeekNamedPipe(input, 0, 0, 0, out uint available, 0)) throw new Failure("parent-disconnected");
        if (available > WatchChallenges.MaximumFrameBytes) throw new Failure("watch-invalidated");
        return available;
    }
    internal unsafe int ReadInput(Span<byte> buffer)
    {
        uint available = AvailableInput();
        if (available == 0) return 0;
        if (available > buffer.Length) throw new Failure("watch-invalidated");
        fixed (byte* pointer = buffer)
        {
            // Sole reader on the actual event loop, only bytes already reported
            // available. Never wait for another line/byte or dispatch to a worker.
            if (!Win32.ReadFile(input, pointer, available, out uint read, 0) || read == 0 || read > available)
                throw new Failure("parent-disconnected");
            return (int)read;
        }
    }
    internal void RequireWritable(int bytes)
    {
        // ReadData/Peek on the write-only stdout handle is not a valid liveness
        // test. Query its actual local pipe state and quota without writing.
        uint size = (uint)Marshal.SizeOf<Win32.FilePipeLocalInformation>();
        if (Win32.NtQueryInformationFile(output, out var status, out var pipe, size, 24) != 0 ||
            status.Status != 0 || status.Information != size || pipe.NamedPipeType != 0 || pipe.NamedPipeState != 3 ||
            pipe.WriteQuotaAvailable < bytes) throw new Failure("parent-disconnected");
    }
    public void Dispose() => process.Dispose();
}
