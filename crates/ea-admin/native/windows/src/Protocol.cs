using System.Security.Cryptography;
using System.Text.Json;

namespace Ea.NativeOperator;

internal sealed class Failure(string code) : Exception
{
    public string Code { get; } = code;
}

internal static class Hex
{
    internal static string Encode(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);
    internal static byte[] Decode(string text)
    {
        if (text.Length % 2 != 0 || text.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new Failure("invalid-request");
        return Convert.FromHexString(text);
    }
}

internal sealed class Request : IDisposable
{
    internal const int MaximumBytes = 65_536;
    internal string Op { get; private init; } = "";
    internal string? Slot { get; private init; }
    internal string? Kind { get; private init; }
    internal string? InstallationId { get; private init; }
    internal byte[]? Data { get; private init; }
    internal bool Presence { get; private init; }
    internal bool Replace { get; private init; }
    internal string? Label { get; private init; }
    internal int MaxBytes { get; private init; }
    internal int TimeoutMs { get; private init; }
    internal static bool IsSecret(string slot) => slot is "database-key" or "draft-key";

    internal static Request Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > MaximumBytes) throw new Failure("request-too-large");
        // Parse data directly from UTF-8 into a wipeable byte array: never make
        // a managed immutable string containing a secret32 supplied by the parent.
        byte[]? data = null;
        try
        {
            var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 2 });
            var strings = new Dictionary<string, string>(StringComparer.Ordinal);
            var numbers = new Dictionary<string, int>(StringComparer.Ordinal);
            var fields = new HashSet<string>(StringComparer.Ordinal);
            bool presence = false, replace = false;
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) throw new Failure("invalid-request");
            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                if (reader.TokenType != JsonTokenType.PropertyName) throw new Failure("invalid-request");
                var name = reader.GetString()!;
                if (!fields.Add(name) || fields.Count > 7 || !reader.Read()) throw new Failure("invalid-request");
                if (name is "max_bytes" or "timeout_ms")
                {
                    if (reader.TokenType != JsonTokenType.Number || !reader.TryGetInt32(out var value)) throw new Failure("invalid-request");
                    numbers.Add(name, value);
                }
                else if (name is "presence" or "replace")
                {
                    if (reader.TokenType is not (JsonTokenType.True or JsonTokenType.False)) throw new Failure("invalid-request");
                    if (name == "presence") presence = reader.GetBoolean(); else replace = reader.GetBoolean();
                }
                else
                {
                    if (reader.TokenType != JsonTokenType.String) throw new Failure("invalid-request");
                    if (name == "data")
                    {
                        // Hex data has a single canonical representation; no JSON escapes.
                        if (reader.ValueIsEscaped || reader.ValueSpan.Length % 2 != 0) throw new Failure("invalid-request");
                        var hex = reader.ValueSpan;
                        data = new byte[hex.Length / 2];
                        static int Nibble(byte c) => c is >= 48 and <= 57 ? c - 48 : c is >= 97 and <= 102 ? c - 87 : throw new Failure("invalid-request");
                        for (int i = 0; i < data.Length; i++) data[i] = (byte)((Nibble(hex[2 * i]) << 4) | Nibble(hex[2 * i + 1]));
                    }
                    else strings.Add(name, reader.GetString()!);
                }
            }
            if (reader.TokenType != JsonTokenType.EndObject || reader.Read() || !strings.TryGetValue("op", out var op)) throw new Failure("invalid-request");
            var allowed = new HashSet<string>(["op", "presence", "installation_id"]);
            switch (op)
            {
                case "account": case "initialize": case "reset": break;
                case "watch-session": allowed.Remove("presence"); break;
                case "private-console-line":
                    allowed.Remove("presence");
                    allowed.UnionWith(["prompt", "max_bytes", "timeout_ms"]);
                    break;
                case "generate": allowed.UnionWith(["slot", "kind", "replace"]); break;
                case "sign": case "wrap-secret": allowed.UnionWith(["slot", "kind", "data"]); break;
                case "contains": case "public-key": case "unwrap-secret": case "delete": allowed.UnionWith(["slot", "kind"]); break;
                default: throw new Failure("invalid-request");
            }
            if (!fields.IsSubsetOf(allowed)) throw new Failure("invalid-request");
            var installation = strings.GetValueOrDefault("installation_id");
            if (installation != null && (installation.Length != 64 || Hex.Decode(installation).Length != 32)) throw new Failure("invalid-request");
            if (installation == null && op is not ("account" or "initialize")) throw new Failure("installation-required");
            if (op == "watch-session") return new Request { Op = op, InstallationId = installation };
            if (op == "private-console-line")
            {
                var label = strings.GetValueOrDefault("prompt");
                int maxBytes = numbers.GetValueOrDefault("max_bytes"), timeoutMs = numbers.GetValueOrDefault("timeout_ms");
                ConsoleLinePolicy.Validate(label, maxBytes, timeoutMs);
                return new Request { Op = op, InstallationId = installation, Label = label, MaxBytes = maxBytes, TimeoutMs = timeoutMs };
            }
            var slot = strings.GetValueOrDefault("slot");
            var kind = strings.GetValueOrDefault("kind");
            if (presence && op is "account" or "public-key" or "contains") throw new Failure("invalid-request");
            if (op is not ("account" or "initialize" or "reset") && (slot == null || slot.Length is < 1 or > 64 || slot.Any(c => !(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')))) throw new Failure("invalid-request");
            if (kind != null && kind is not ("ed25519" or "secret32")) throw new Failure("invalid-request");
            if (op == "generate" && kind == null) throw new Failure("invalid-request");
            if (slot != null && kind != null && IsSecret(slot) != (kind == "secret32")) throw new Failure("invalid-request");
            if (op == "sign" && IsSecret(slot!)) throw new Failure("invalid-request");
            if (op is "wrap-secret" or "unwrap-secret" && !IsSecret(slot!)) throw new Failure("invalid-request");
            if (op is "sign" or "wrap-secret" && data == null) throw new Failure("invalid-request");
            if (op == "wrap-secret" && data!.Length != 32) throw new Failure("invalid-request");
            if (op == "sign" && slot != "writer-signing" && !presence) throw new Failure("presence-required");
            if (replace && (op != "generate" || slot != "operator-instance" || kind != "ed25519")) throw new Failure("invalid-request");
            if ((replace || op == "reset") && !presence) throw new Failure("presence-required");
            return new Request { Op = op, Slot = slot, Kind = kind, InstallationId = installation, Data = data, Presence = presence, Replace = replace };
        }
        catch (Exception e) when (e is Failure or JsonException or InvalidOperationException or ArgumentException)
        {
            if (data != null) CryptographicOperations.ZeroMemory(data);
            throw e is Failure f ? f : new Failure("invalid-request");
        }
    }
    public void Dispose() { if (Data != null) CryptographicOperations.ZeroMemory(Data); }
}

internal static class Transport
{
    internal sealed class Frame(byte[] bytes, bool watch) : IDisposable
    {
        internal byte[] Bytes { get; } = bytes;
        internal bool Watch { get; } = watch;
        public void Dispose() => CryptographicOperations.ZeroMemory(Bytes);
    }
    internal static async Task<Frame> ReadAsync(Stream input)
    {
        var buffer = new byte[Request.MaximumBytes + 1];
        try
        {
            int total = 0;
            bool firstLineSeen = false;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (true)
            {
                // Console streams can ignore cancellation once a synchronous
                // pipe read is in flight. Bound the wait itself as well.
                int count = await input.ReadAsync(buffer.AsMemory(total), deadline.Token).AsTask().WaitAsync(deadline.Token);
                if (count == 0) return new Frame(buffer.AsSpan(0, total).ToArray(), false);
                total += count;
                if (total > Request.MaximumBytes) throw new Failure("request-too-large");
                if (!firstLineSeen)
                {
                    int newline = Array.IndexOf(buffer, (byte)10, 0, total);
                    if (newline >= 0)
                    {
                        firstLineSeen = true;
                        // Only the watch operation changes the EOF contract.
                        // This is a framing hint, never authorization: Parse
                        // below still rejects duplicate/unknown/invalid fields.
                        if (HasWatchOp(buffer.AsSpan(0, newline)))
                        {
                            // No pre-ready second frame or post-line whitespace.
                            // Later challenges/EOF belong to the native watch loop.
                            if (total != newline + 1) throw new Failure("invalid-request");
                            return new Frame(buffer.AsSpan(0, newline).ToArray(), true);
                        }
                    }
                }
            }
        }
        catch (Exception e) when (e is OperationCanceledException or IOException) { throw new Failure("io-failed"); }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }
    private static bool HasWatchOp(ReadOnlySpan<byte> line)
    {
        // No JsonDocument/string copy of data: ordinary requests can contain a
        // secret32, even though only watch-session opts into line framing.
        try
        {
            var reader = new Utf8JsonReader(line, new JsonReaderOptions { MaxDepth = 2 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) return false;
            bool watch = false;
            while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                if (reader.TokenType != JsonTokenType.PropertyName) return false;
                bool operation = reader.ValueTextEquals("op"u8);
                if (!reader.Read()) return false;
                watch |= operation && reader.TokenType == JsonTokenType.String && reader.ValueTextEquals("watch-session"u8);
                reader.Skip();
            }
            return reader.TokenType == JsonTokenType.EndObject && !reader.Read() && watch;
        }
        catch (JsonException) { return false; }
    }
    internal static void WriteLine(Stream output, byte[] response)
    {
        try
        {
            if (response.Length > Request.MaximumBytes) throw new Failure("native-failed");
            output.Write(response); output.WriteByte(10); output.Flush();
        }
        finally { CryptographicOperations.ZeroMemory(response); }
    }
    internal static byte[] WatchReply(string installationId, bool ready)
    {
        if (installationId.Length != 64 || Hex.Decode(installationId).Length != 32) throw new Failure("native-failed");
        return ready
            ? JsonSerializer.SerializeToUtf8Bytes(new { ok = true, installation_id = installationId, ready = true })
            : JsonSerializer.SerializeToUtf8Bytes(new { ok = true, installation_id = installationId, invalidated = true });
    }
    internal static byte[] WatchAcknowledgement(string installationId, string challenge)
    {
        if (installationId.Length != 64 || Hex.Decode(installationId).Length != 32 ||
            challenge.Length != 64 || Hex.Decode(challenge).Length != 32) throw new Failure("native-failed");
        return JsonSerializer.SerializeToUtf8Bytes(new { ok = true, installation_id = installationId, challenge });
    }
    internal static byte[] Error(Exception error) => JsonSerializer.SerializeToUtf8Bytes(new { ok = false, code = error is Failure f ? f.Code : "native-failed" });
    internal static byte[] SecretReply(string installationId, ReadOnlySpan<byte> secret)
    {
        if (installationId.Length != 64 || Hex.Decode(installationId).Length != 32 || secret.Length != 32) throw new Failure("native-failed");
        // The plaintext secret never becomes an immutable managed string.
        var prefix = System.Text.Encoding.ASCII.GetBytes("{\"ok\":true,\"installation_id\":\"" + installationId + "\",\"secret\":\"");
        var bytes = new byte[prefix.Length + 64 + 2];
        prefix.CopyTo(bytes, 0);
        ReadOnlySpan<byte> digits = "0123456789abcdef"u8;
        for (int i = 0; i < 32; i++) { bytes[prefix.Length + 2 * i] = digits[secret[i] >> 4]; bytes[prefix.Length + 2 * i + 1] = digits[secret[i] & 15]; }
        bytes[^2] = (byte)'"'; bytes[^1] = (byte)'}';
        return bytes;
    }
    internal static byte[] LineReply(string installationId, ReadOnlySpan<char> line)
    {
        if (installationId.Length != 64 || Hex.Decode(installationId).Length != 32 ||
            new System.Text.UTF8Encoding(false, true).GetByteCount(line) > ConsoleLinePolicy.MaximumBytes) throw new Failure("native-failed");
        using var buffer = new MemoryStream();
        try
        {
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteBoolean("ok", true);
                writer.WriteString("installation_id", installationId);
                writer.WriteString("line", line);
                writer.WriteEndObject();
            }
            if (buffer.Length > Request.MaximumBytes) throw new Failure("native-failed");
            return buffer.ToArray(); // caller owns and clears the sole response copy
        }
        finally { CryptographicOperations.ZeroMemory(buffer.GetBuffer().AsSpan()); }
    }
}
