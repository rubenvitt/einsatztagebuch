using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace Ea.NativeOperator;

internal static class Win32
{
    internal const uint TokenQuery = 8;
    internal const uint TokenImpersonate = 4;
    internal const uint TokenDuplicate = 2;
    // SHGetKnownFolderPath's explicit token contract, including the documented
    // conditional DUPLICATE right. Other process tokens remain query-only.
    internal const uint KnownFolderTokenAccess = TokenQuery | TokenImpersonate | TokenDuplicate;
    [DllImport("kernel32.dll")] internal static extern nint GetCurrentProcess();
    [DllImport("kernel32.dll")] internal static extern nint GetCurrentThread();
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenProcessToken(nint process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool OpenThreadToken(nint thread, uint access, bool openAsSelf, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool GetTokenInformation(SafeAccessTokenHandle token, int type, nint buffer, uint length, out uint returned);
    [DllImport("advapi32.dll")] internal static extern bool IsValidSid(nint sid);
    [DllImport("advapi32.dll")] internal static extern uint GetLengthSid(nint sid);
    [DllImport("userenv.dll", SetLastError = true)] internal static extern bool GetProfileType(out uint flags);
    [DllImport("shell32.dll")] internal static extern int SHGetKnownFolderPath(in Guid folder, uint flags, SafeAccessTokenHandle token, out nint path);
    [DllImport("kernel32.dll")] internal static extern nint LocalFree(nint memory);
    [DllImport("kernel32.dll")] internal static extern nint GetStdHandle(int value);
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern SafeFileHandle CreateFile(string name, uint access, uint share, nint security, uint creation, uint flags, nint template);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetConsoleMode(SafeFileHandle handle, out uint mode);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetConsoleMode(SafeFileHandle handle, uint mode);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool FlushConsoleInputBuffer(SafeFileHandle input);
    [DllImport("kernel32.dll", EntryPoint = "WriteConsoleW", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool WriteConsole(SafeFileHandle output, string text, uint count, out uint written, nint reserved);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", EntryPoint = "ReadConsoleInputExW", SetLastError = true)] internal static extern unsafe bool ReadConsoleInputEx(SafeFileHandle input, InputRecord* records, uint length, out uint read, ushort flags);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate bool ConsoleControlHandler(uint kind);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool SetConsoleCtrlHandler(ConsoleControlHandler handler, bool add);
    [StructLayout(LayoutKind.Explicit, Size = 20)] internal struct InputRecord
    {
        [FieldOffset(0)] internal ushort EventType;
        [FieldOffset(4)] internal int KeyDown;
        [FieldOffset(8)] internal ushort RepeatCount;
        [FieldOffset(10)] internal ushort VirtualKeyCode;
        [FieldOffset(12)] internal ushort VirtualScanCode;
        [FieldOffset(14)] internal ushort UnicodeChar;
        [FieldOffset(16)] internal uint ControlKeyState;
    }
    [DllImport("kernel32.dll")] internal static extern uint GetFileType(nint handle);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetNamedPipeInfo(nint handle, out uint flags, out uint outputSize, out uint inputSize, out uint maxInstances);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetNamedPipeClientProcessId(nint handle, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool GetNamedPipeServerProcessId(nint handle, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern bool PeekNamedPipe(nint handle, nint buffer, uint size, nint read, out uint available, nint left);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern unsafe bool ReadFile(nint file, byte* buffer, uint count, out uint read, nint overlapped);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] internal static extern uint GetDriveType(string path);
    [DllImport("ntdll.dll")] internal static extern int NtQueryInformationProcess(nint process, int infoClass, out ProcessBasicInformation info, int length, out int returned);
    [StructLayout(LayoutKind.Sequential)] internal struct ProcessBasicInformation { internal nint Reserved1, Peb, Reserved2a, Reserved2b, Pid, ParentPid; }
    [DllImport("ntdll.dll")] internal static extern int NtQueryInformationFile(nint file, out IoStatusBlock status, out FilePipeLocalInformation information, uint length, int infoClass);
    [StructLayout(LayoutKind.Sequential)] internal struct IoStatusBlock { internal nint Status; internal nuint Information; }
    [StructLayout(LayoutKind.Sequential)] internal struct FilePipeLocalInformation
    {
        internal uint NamedPipeType, NamedPipeConfiguration, MaximumInstances, CurrentInstances,
            InboundQuota, ReadDataAvailable, OutboundQuota, WriteQuotaAvailable, NamedPipeState, NamedPipeEnd;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Blob { internal int Length; internal nint Data; }
    [DllImport("crypt32.dll", SetLastError = true)] internal static extern bool CryptProtectData(ref Blob input, nint description, ref Blob entropy, nint reserved, nint prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] internal static extern bool CryptUnprotectData(ref Blob input, nint description, ref Blob entropy, nint reserved, nint prompt, uint flags, out Blob output);
    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool CredRead(string target, uint type, uint flags, out nint credential);
    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool CredWrite(ref Credential credential, uint flags);
    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern bool CredDelete(string target, uint type, uint flags);
    [DllImport("advapi32.dll")] internal static extern void CredFree(nint credential);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct Credential
    {
        internal uint Flags, Type;
        [MarshalAs(UnmanagedType.LPWStr)] internal string TargetName;
        [MarshalAs(UnmanagedType.LPWStr)] internal string Comment;
        internal long LastWritten;
        internal uint CredentialBlobSize;
        internal nint CredentialBlob;
        internal uint Persist, AttributeCount;
        internal nint Attributes, TargetAlias, UserName;
    }
    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)] internal static extern bool WTSQuerySessionInformation(nint server, uint session, int infoClass, out nint buffer, out uint length);
    [DllImport("wtsapi32.dll")] internal static extern void WTSFreeMemory(nint buffer);
    [DllImport("wtsapi32.dll", SetLastError = true)] internal static extern bool WTSRegisterSessionNotification(nint window, uint flags);
    [DllImport("wtsapi32.dll")] internal static extern bool WTSUnRegisterSessionNotification(nint window);
    [DllImport("user32.dll")] internal static extern nint GetShellWindow();
    [DllImport("user32.dll")] internal static extern uint GetWindowThreadProcessId(nint hwnd, out uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] internal static extern nint GetModuleHandle(string? module);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] internal delegate nint WindowProc(nint hwnd, uint message, nuint wparam, nint lparam);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct WindowClass
    {
        internal uint Size, Style;
        internal WindowProc Procedure;
        internal int ClassExtra, WindowExtra;
        internal nint Instance, Icon, Cursor, Background;
        internal string? MenuName;
        internal string ClassName;
        internal nint SmallIcon;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct Message
    {
        internal nint Hwnd;
        internal uint Value;
        internal nuint WParam;
        internal nint LParam;
        internal uint Time;
        internal int X, Y;
        internal uint Private;
    }
    [DllImport("user32.dll", EntryPoint = "RegisterClassExW", CharSet = CharSet.Unicode)] internal static extern ushort RegisterClassEx(ref WindowClass windowClass);
    [DllImport("user32.dll", EntryPoint = "CreateWindowExW", CharSet = CharSet.Unicode)] internal static extern nint CreateWindowEx(uint extendedStyle, string className, string title, uint style, int x, int y, int width, int height, nint parent, nint menu, nint instance, nint parameter);
    [DllImport("user32.dll", EntryPoint = "DefWindowProcW")] internal static extern nint DefWindowProc(nint hwnd, uint message, nuint wparam, nint lparam);
    [DllImport("user32.dll")] internal static extern bool DestroyWindow(nint window);
    [DllImport("user32.dll", EntryPoint = "UnregisterClassW", CharSet = CharSet.Unicode)] internal static extern bool UnregisterClass(string className, nint instance);
    [DllImport("user32.dll")] internal static extern bool ShowWindow(nint hwnd, int command);
    [DllImport("user32.dll")] internal static extern bool SetForegroundWindow(nint hwnd);
    [DllImport("user32.dll", EntryPoint = "PeekMessageW")] internal static extern bool PeekMessage(out Message message, nint window, uint min, uint max, uint remove);
    [DllImport("user32.dll")] internal static extern bool TranslateMessage(ref Message message);
    [DllImport("user32.dll", EntryPoint = "DispatchMessageW")] internal static extern nint DispatchMessage(ref Message message);
}
