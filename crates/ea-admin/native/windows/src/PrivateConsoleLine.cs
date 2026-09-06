using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Ea.NativeOperator;

internal static class PrivateConsoleLine
{
    internal static unsafe void Read(string label, int maximumBytes, int timeoutMs, ConsoleLineBuffer line, Action recheck)
    {
        ConsoleLinePolicy.Validate(label, maximumBytes, timeoutMs);
        // Fixed console devices, never stdin/stdout, files, environment paths or
        // a newly allocated console. Missing/detached consoles fail closed.
        const uint readWrite = 0xc0000000, shareReadWrite = 3, openExisting = 3;
        using var input = Win32.CreateFile("CONIN$", readWrite, shareReadWrite, 0, openExisting, 0, 0);
        using var output = Win32.CreateFile("CONOUT$", readWrite, shareReadWrite, 0, openExisting, 0, 0);
        if (input.IsInvalid || output.IsInvalid || Win32.GetFileType(input.DangerousGetHandle()) != 2 ||
            Win32.GetFileType(output.DangerousGetHandle()) != 2 || !Win32.GetConsoleMode(input, out uint originalMode) ||
            !Win32.GetConsoleMode(output, out _)) throw new Failure("console-required");

        int cancelled = 0;
        Win32.ConsoleControlHandler handler = kind =>
        {
            if (kind is not (0 or 1)) return false;
            Interlocked.Exchange(ref cancelled, 1);
            return true;
        };
        bool registered = false, changed = false;
        Span<Win32.InputRecord> records = stackalloc Win32.InputRecord[32];
        try
        {
            recheck();
            registered = Win32.SetConsoleCtrlHandler(handler, true);
            if (!registered) throw new Failure("console-unavailable");
            uint privateMode = ConsoleLinePolicy.InputMode(originalMode);
            changed = Win32.SetConsoleMode(input, privateMode);
            if (!changed || !Win32.GetConsoleMode(input, out uint actualMode) || actualMode != privateMode) throw new Failure("console-mode-failed");
            // Consume only input entered after this prompt, not stale typeahead.
            if (!Win32.FlushConsoleInputBuffer(input)) throw new Failure("console-unavailable");
            string prompt = ConsoleLinePolicy.Prompt(label);
            if (!Win32.WriteConsole(output, prompt, (uint)prompt.Length, out uint written, 0) || written != prompt.Length) throw new Failure("console-unavailable");
            var clock = Stopwatch.StartNew();
            long nextRecheck = 0;
            while (true)
            {
                if (Volatile.Read(ref cancelled) != 0) throw new Failure("console-cancelled");
                long elapsed = clock.ElapsedMilliseconds;
                if (elapsed >= timeoutMs) throw new Failure("console-timeout");
                if (elapsed >= nextRecheck)
                {
                    recheck();
                    if (!Win32.GetConsoleMode(input, out actualMode) || actualMode != privateMode) throw new Failure("console-mode-changed");
                    nextRecheck = elapsed + 100;
                }
                uint wait = Win32.WaitForSingleObject(input, (uint)Math.Min(50, Math.Max(0, timeoutMs - clock.ElapsedMilliseconds)));
                if (wait == 258) continue; // WAIT_TIMEOUT; total deadline is never reset
                if (wait != 0) throw new Failure("console-unavailable");
                uint read;
                fixed (Win32.InputRecord* pointer = records)
                {
                    // NOWAIT closes the wait/read race if another console reader
                    // drains an event. A plain ReadConsoleInput could block here.
                    if (!Win32.ReadConsoleInputEx(input, pointer, (uint)records.Length, out read, 2) || read > records.Length) throw new Failure("console-unavailable");
                }
                try
                {
                    if (clock.ElapsedMilliseconds >= timeoutMs) throw new Failure("console-timeout");
                    for (int i = 0; i < read; i++)
                        if (line.Accept(records[i]))
                        {
                            recheck();
                            if (clock.ElapsedMilliseconds >= timeoutMs) throw new Failure("console-timeout");
                            if (Volatile.Read(ref cancelled) != 0) throw new Failure("console-cancelled");
                            // Only a newline is written here; entered text is
                            // never echoed, including on validation failures.
                            if (!Win32.WriteConsole(output, "\r\n", 2, out written, 0) || written != 2) throw new Failure("console-unavailable");
                            return;
                        }
                }
                finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(records)); }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(records));
            bool restored = !changed || (Win32.SetConsoleMode(input, originalMode) &&
                Win32.GetConsoleMode(input, out uint restoredMode) && restoredMode == originalMode);
            if (registered) Win32.SetConsoleCtrlHandler(handler, false);
            GC.KeepAlive(handler);
            if (!restored) throw new Failure("console-mode-restore-failed");
        }
    }
}
