using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Ea.NativeOperator;

internal static class ConsoleLinePolicy
{
    internal const int MaximumBytes = 4096;
    internal const int MaximumTimeoutMs = 300_000;
    internal static string Prompt(string label) => label switch
    {
        "external-identity-confirmation" => "Externen Identitätsabgleich bestätigen. Genau extern-geprueft eingeben: ",
        "authority-subject-id" => "Authority-Subject-ID: ",
        "display-name" => "Anzeigename: ",
        "function-label" => "Funktionsbezeichnung: ",
        _ => throw new Failure("invalid-request")
    };
    internal static void Validate(string? label, int maximumBytes, int timeoutMs)
    {
        if (label == null || maximumBytes is < 1 or > MaximumBytes || timeoutMs is < 1 or > MaximumTimeoutMs) throw new Failure("invalid-request");
        _ = Prompt(label);
    }
    // Raw Unicode key events; no echo, cooked line input, Ctrl+C processing,
    // quick-edit suspension or VT byte-sequence translation. Preserve other bits.
    internal static uint InputMode(uint original) => (original | 0x0080u) & ~0x0247u;
}

// Bounded Unicode event state machine shared by the native reader and portable
// tests. Input stays in a clearable, pinned UTF-16 buffer, never an immutable
// string. Byte limits are measured in strict UTF-8, not UTF-16 code units.
internal sealed class ConsoleLineBuffer : IDisposable
{
    private readonly char[] buffer;
    private readonly int maximumBytes;
    private int length, byteCount;
    private char pendingHigh;
    private bool complete;
    internal ConsoleLineBuffer(int maximumBytes)
    {
        if (maximumBytes is < 1 or > ConsoleLinePolicy.MaximumBytes) throw new Failure("invalid-request");
        this.maximumBytes = maximumBytes;
        buffer = GC.AllocateArray<char>(maximumBytes, pinned: true);
    }
    internal ReadOnlySpan<char> Line => complete && pendingHigh == '\0' ? buffer.AsSpan(0, length) : throw new Failure("console-invalid-input");
    internal bool Accept(Win32.InputRecord record)
    {
        if (complete) throw new Failure("console-invalid-input");
        if (record.EventType != 1 || record.KeyDown == 0 || record.RepeatCount == 0) return false;
        char value = (char)record.UnicodeChar;
        if (record.VirtualKeyCode is 0x1b or 0x03 || value is '\x03' or '\x1a' or '\x1b' ||
            ((record.ControlKeyState & 0x000c) != 0 && record.VirtualKeyCode == 0x43)) throw new Failure("console-cancelled");
        for (int i = 0; i < record.RepeatCount; i++)
        {
            if (record.VirtualKeyCode == 0x0d || value is '\r' or '\n')
            {
                if (pendingHigh != '\0') throw new Failure("console-invalid-input");
                complete = true;
                return true;
            }
            if (record.VirtualKeyCode == 0x08 || value == '\b') { Backspace(); continue; }
            if (value == '\0') continue; // modifiers/navigation carry no Unicode character
            Append(value);
        }
        return false;
    }
    private void Append(char value)
    {
        Rune scalar;
        if (pendingHigh != '\0')
        {
            if (!Rune.TryCreate(pendingHigh, value, out scalar)) throw new Failure("console-invalid-input");
            pendingHigh = '\0';
        }
        else
        {
            if (char.IsHighSurrogate(value)) { pendingHigh = value; return; }
            if (!Rune.TryCreate(value, out scalar)) throw new Failure("console-invalid-input");
        }
        if (Rune.IsControl(scalar) || scalar.Value is 0x2028 or 0x2029) throw new Failure("console-invalid-input");
        if (byteCount + scalar.Utf8SequenceLength > maximumBytes) throw new Failure("console-input-too-large");
        length += scalar.EncodeToUtf16(buffer.AsSpan(length));
        byteCount += scalar.Utf8SequenceLength;
    }
    private void Backspace()
    {
        if (pendingHigh != '\0') { pendingHigh = '\0'; return; }
        if (length == 0) return;
        if (Rune.DecodeLastFromUtf16(buffer.AsSpan(0, length), out var scalar, out int units) != OperationStatus.Done) throw new Failure("console-invalid-input");
        buffer.AsSpan(length - units, units).Clear();
        length -= units;
        byteCount -= scalar.Utf8SequenceLength;
    }
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));
        pendingHigh = '\0'; length = byteCount = 0; complete = false;
    }
}
