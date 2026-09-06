using System.Diagnostics;
using System.Runtime.InteropServices;
using Windows.Foundation;
using Windows.Security.Credentials.UI;

namespace Ea.NativeOperator;

internal sealed class SessionWindow : IDisposable
{
    private readonly NativeAccount account;
    private readonly Win32.WindowProc procedure;
    private readonly string className = "Einsatzarchiv.Operator." + Environment.ProcessId;
    private readonly nint instance = Win32.GetModuleHandle(null);
    private nint window;
    private bool interrupted;
    internal SessionWindow(NativeAccount account)
    {
        this.account = account;
        procedure = WindowProcedure;
        var wc = new Win32.WindowClass { Size = (uint)Marshal.SizeOf<Win32.WindowClass>(), Procedure = procedure, Instance = instance, ClassName = className };
        if (Win32.RegisterClassEx(ref wc) == 0) throw new Failure("session-unavailable");
        window = Win32.CreateWindowEx(0, className, "Einsatzarchiv – Identität bestätigen", 0x00C80000, 150, 150, 420, 140, 0, 0, instance, 0);
        if (window == 0 || !Win32.WTSRegisterSessionNotification(window, 0)) { Dispose(); throw new Failure("session-unavailable"); }
    }
    private nint WindowProcedure(nint hwnd, uint message, nuint wparam, nint lparam)
    {
        // Latch current-session transitions, including lock/logoff/disconnect.
        // A later unlock must not revive an operation; WM_CLOSE cancels consent.
        if (message == 0x02B1 && WatchLifetime.SessionChangeInvalidates(account.Session, unchecked((uint)lparam), wparam)) interrupted = true;
        if (message == 0x0010) { interrupted = true; return 0; }
        return Win32.DefWindowProc(hwnd, message, wparam, lparam);
    }
    private void Pump()
    {
        while (Win32.PeekMessage(out var message, 0, 0, 0, 1))
        { Win32.TranslateMessage(ref message); Win32.DispatchMessage(ref message); }
    }
    internal bool Locked()
    {
        Pump();
        if (interrupted || !account.IsInteractiveAccount()) return true;
        // WTSINFOEX: DWORD Level, then 8-byte-aligned union containing Level1.
        // Supported OS >= build 22000 avoids the Windows 7 reversed flag bug.
        if (!Win32.WTSQuerySessionInformation(0, account.Session, 25, out var buffer, out var length)) return true;
        try
        {
            return length < 20 || Marshal.ReadInt32(buffer, 0) != 1 ||
                unchecked((uint)Marshal.ReadInt32(buffer, 8)) != account.Session ||
                Marshal.ReadInt32(buffer, 12) != 0 || // WTSActive
                Marshal.ReadInt32(buffer, 16) != 1;   // WTS_SESSIONSTATE_UNLOCK
        }
        finally { Win32.WTSFreeMemory(buffer); }
    }
    internal void RequireUnlocked() { if (Locked()) throw new Failure("locked"); }
    internal void VerifyPresence()
    {
        RequireUnlocked(); account.Recheck();
        Win32.ShowWindow(window, 5);
        Win32.SetForegroundWindow(window);
        // SDK projection of IUserConsentVerifierInterop, with our live owner
        // window. No generic UWP call, account picker or credential collection.
        var consent = UserConsentVerifierInterop.RequestVerificationForWindowAsync(window, "Identität für Einsatzarchiv bestätigen");
        var timer = Stopwatch.StartNew();
        try
        {
            while (consent.Status == AsyncStatus.Started)
            {
                RequireUnlocked();
                if (timer.Elapsed > TimeSpan.FromSeconds(45)) throw new Failure("presence-timeout");
                Thread.Sleep(15);
            }
            if (consent.Status != AsyncStatus.Completed || consent.GetResults() != UserConsentVerificationResult.Verified) throw new Failure("presence-denied");
            account.Recheck(); RequireUnlocked();
        }
        finally
        {
            if (consent.Status == AsyncStatus.Started) consent.Cancel();
            consent.Close();
            Win32.ShowWindow(window, 0);
        }
    }
    public void Dispose()
    {
        if (window != 0) { Win32.WTSUnRegisterSessionNotification(window); Win32.DestroyWindow(window); window = 0; }
        Win32.UnregisterClass(className, instance);
        GC.KeepAlive(procedure);
    }
}
