using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Ea.NativeOperator;

internal static class ConsoleLineTests
{
    internal static void Run(Action<bool, string> check)
    {
        const string id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        static Win32.InputRecord Key(char value, ushort key = 0, ushort repeats = 1, bool down = true) => new() {
            EventType = 1, KeyDown = down ? 1 : 0, UnicodeChar = value, VirtualKeyCode = key, RepeatCount = repeats
        };
        void Failure(Action action, string code) {
            try { action(); throw new Exception("accepted console input expected to fail: " + code); }
            catch (Ea.NativeOperator.Failure error) { check(error.Code == code, code); }
        }
        void InvalidRequest(string fields, string code = "invalid-request") => Failure(() => {
            using var request = Request.Parse(Encoding.UTF8.GetBytes("{\"op\":\"private-console-line\",\"installation_id\":\"" + id + "\"," + fields + "}"));
        }, code);
        foreach (string fields in new[] {
            "\"prompt\":\"password\",\"max_bytes\":32,\"timeout_ms\":1000",
            "\"prompt\":\"display-name\",\"max_bytes\":0,\"timeout_ms\":1000",
            "\"prompt\":\"display-name\",\"max_bytes\":4097,\"timeout_ms\":1000",
            "\"prompt\":\"display-name\",\"max_bytes\":1,\"timeout_ms\":0",
            "\"prompt\":\"display-name\",\"max_bytes\":1,\"timeout_ms\":300001",
            "\"prompt\":\"display-name\",\"max_bytes\":1.0,\"timeout_ms\":1000",
            "\"prompt\":\"display-name\",\"max_bytes\":\"32\",\"timeout_ms\":1000",
            "\"prompt\":\"display-name\",\"max_bytes\":-1,\"timeout_ms\":1000",
            "\"prompt\":\"display-name\",\"max_bytes\":1,\"timeout_ms\":2147483648",
            "\"prompt\":\"display-name\",\"max_bytes\":32",
            "\"prompt\":\"display-name\",\"timeout_ms\":1000",
            "\"max_bytes\":32,\"timeout_ms\":1000",
            "\"prompt\":\"display-name\",\"max_bytes\":32,\"timeout_ms\":1000,\"presence\":false",
            "\"prompt\":\"display-name\",\"max_bytes\":32,\"timeout_ms\":1000,\"line\":\"injected\"",
            "\"prompt\":\"display-name\",\"max_bytes\":32,\"max_bytes\":64,\"timeout_ms\":1000",
            "\"prompt\":\"display-name\",\"max_bytes\":32,\"\\u006dax_bytes\":64,\"timeout_ms\":1000"
        }) InvalidRequest(fields);
        Failure(() => { using var r = Request.Parse("{\"op\":\"private-console-line\",\"prompt\":\"display-name\",\"max_bytes\":32,\"timeout_ms\":1000}"u8); }, "installation-required");
        Failure(() => { using var r = Request.Parse("{\"op\":\"account\",\"max_bytes\":32}"u8); }, "invalid-request");
        using (var request = Request.Parse(Encoding.UTF8.GetBytes("{\"op\":\"private-console-line\",\"installation_id\":\"" + id + "\",\"prompt\":\"authority-subject-id\",\"max_bytes\":4096,\"timeout_ms\":300000}")))
            check(request.Label == "authority-subject-id" && request.MaxBytes == 4096 && request.TimeoutMs == 300000, "exact console limits carried to reader");
        check(ConsoleLinePolicy.Prompt("external-identity-confirmation").Contains("extern-geprueft", StringComparison.Ordinal), "literal confirmation token in fixed prompt");
        check(Marshal.SizeOf<Win32.InputRecord>() == 20 && Marshal.OffsetOf<Win32.InputRecord>("UnicodeChar").ToInt32() == 14, "Windows Unicode input record ABI");
        uint original = 0x03ff;
        uint mode = ConsoleLinePolicy.InputMode(original);
        check((mode & 0x0247) == 0 && (mode & 0x80) != 0, "echo/cooked/processed/VT/quick-edit disabled");
        check((mode & 0x0138) == (original & 0x0138), "unrelated console mode bits preserved");
        using (var line = new ConsoleLineBuffer(9)) {
            foreach (char c in " ä😀\"\\") line.Accept(Key(c)); // 1 + 2 + 4 + 1 + 1 UTF-8 bytes
            check(line.Accept(Key('\r', 13)), "Unicode line finishes on Enter");
            check(line.Line.SequenceEqual(" ä😀\"\\"), "Unicode preserved without trimming or normalization");
            var response = Transport.LineReply(id, line.Line);
            using var json = JsonDocument.Parse(response);
            check(json.RootElement.EnumerateObject().Count() == 3 && json.RootElement.GetProperty("ok").GetBoolean() &&
                json.RootElement.GetProperty("installation_id").GetString() == id && json.RootElement.GetProperty("line").GetString() == " ä😀\"\\",
                "closed escaped line reply contains only public ID and entered line");
            var view = line.Line;
            line.Dispose();
            check(view.IndexOfAnyExcept('\0') == -1, "owned input buffer zeroed on disposal");
        }
        using (var line = new ConsoleLineBuffer(4)) {
            line.Accept(Key('\ud83d')); line.Accept(Key('\ude00')); line.Accept(Key('\b', 8));
            line.Accept(Key('ä', repeats: 2)); line.Accept(Key('\r', 13));
            check(line.Line.SequenceEqual("ää"), "backspace removes entire supplementary scalar and reclaims UTF-8 budget");
        }
        using (var line = new ConsoleLineBuffer(1)) {
            line.Accept(Key('\ud83d')); line.Accept(Key('\b', 8)); line.Accept(Key('x')); line.Accept(Key('\r', 13));
            check(line.Line.SequenceEqual("x"), "backspace cancels incomplete surrogate");
        }
        using (var line = new ConsoleLineBuffer(1)) {
            check(!line.Accept(Key('x', down: false)) && !line.Accept(new Win32.InputRecord { EventType = 2 }), "key-up and mouse events ignored");
            line.Accept(Key('\0', 0x25)); line.Accept(Key('\r', 13));
            check(line.Line.IsEmpty, "navigation not copied and empty line allowed");
        }
        using (var line = new ConsoleLineBuffer(2)) Failure(() => line.Accept(Key('ä', repeats: 2)), "console-input-too-large");
        using (var line = new ConsoleLineBuffer(3)) Failure(() => { line.Accept(Key('\ud83d')); line.Accept(Key('\ude00')); }, "console-input-too-large");
        using (var line = new ConsoleLineBuffer(8)) Failure(() => line.Accept(Key('\udc00')), "console-invalid-input");
        using (var line = new ConsoleLineBuffer(8)) Failure(() => { line.Accept(Key('\ud800')); line.Accept(Key('a')); }, "console-invalid-input");
        using (var line = new ConsoleLineBuffer(8)) Failure(() => { line.Accept(Key('\ud800')); line.Accept(Key('\r', 13)); }, "console-invalid-input");
        foreach (char c in new[] { '\t', '\x7f', '\u2028', '\u2029' }) {
            using var line = new ConsoleLineBuffer(8);
            Failure(() => line.Accept(Key(c)), "console-invalid-input");
        }
        foreach (char c in new[] { '\x03', '\x1a', '\x1b' }) {
            using var line = new ConsoleLineBuffer(8);
            Failure(() => line.Accept(Key(c)), "console-cancelled");
        }
        using (var line = new ConsoleLineBuffer(8)) {
            var ctrlC = Key('\0', 0x43); ctrlC.ControlKeyState = 8;
            Failure(() => line.Accept(ctrlC), "console-cancelled");
        }
        Failure(() => Transport.LineReply(id, new string('a', 4097)), "native-failed");
        using (var line = new ConsoleLineBuffer(4096)) {
            line.Accept(Key('"', repeats: 4096)); line.Accept(Key('\r', 13));
            check(Transport.LineReply(id, line.Line).Length <= Request.MaximumBytes, "worst-case JSON escaping stays bounded");
        }
    }
}
