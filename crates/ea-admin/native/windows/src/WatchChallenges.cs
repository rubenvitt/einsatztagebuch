using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Ea.NativeOperator;

// Framing/state only. Native reads, coverage checks and ACK writes all occur on
// SessionWatch's STA event loop; there is no independently live ACK worker.
internal sealed class WatchChallenges : IDisposable
{
    internal const int MaximumFrameBytes = 1024; // including LF
    internal const int MaximumChallenges = 16_384; // bounded replay memory
    private readonly byte[] frame = new byte[MaximumFrameBytes];
    private readonly HashSet<string> consumed = new(StringComparer.Ordinal);
    private int length;
    private bool awaitingAcknowledgement, invalidated;

    internal string? Append(ReadOnlySpan<byte> input)
    {
        try
        {
            if (invalidated || awaitingAcknowledgement || input.Length > MaximumFrameBytes - length) throw new Failure("watch-invalidated");
            input.CopyTo(frame.AsSpan(length)); length += input.Length;
            int newline = frame.AsSpan(0, length).IndexOf((byte)10);
            if (newline < 0)
            {
                if (length == MaximumFrameBytes) throw new Failure("watch-invalidated");
                return null;
            }
            if (newline != length - 1) throw new Failure("watch-invalidated"); // only one outstanding frame
            string challenge = Parse(frame.AsSpan(0, newline));
            if (consumed.Count >= MaximumChallenges || !consumed.Add(challenge)) throw new Failure("watch-invalidated");
            awaitingAcknowledgement = true;
            return challenge;
        }
        catch { invalidated = true; throw new Failure("watch-invalidated"); }
    }
    private static string Parse(ReadOnlySpan<byte> input)
    {
        var reader = new Utf8JsonReader(input, new JsonReaderOptions { MaxDepth = 1 });
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject ||
            !reader.Read() || reader.TokenType != JsonTokenType.PropertyName || reader.ValueIsEscaped || !reader.ValueTextEquals("challenge"u8) ||
            !reader.Read() || reader.TokenType != JsonTokenType.String || reader.ValueIsEscaped || reader.ValueSpan.Length != 64)
            throw new Failure("watch-invalidated");
        foreach (byte digit in reader.ValueSpan)
            if (!(digit is >= (byte)'0' and <= (byte)'9' or >= (byte)'a' and <= (byte)'f')) throw new Failure("watch-invalidated");
        string challenge = Encoding.ASCII.GetString(reader.ValueSpan);
        if (!reader.Read() || reader.TokenType != JsonTokenType.EndObject || reader.Read()) throw new Failure("watch-invalidated");
        return challenge;
    }
    internal void Acknowledged()
    {
        if (invalidated || !awaitingAcknowledgement) { invalidated = true; throw new Failure("watch-invalidated"); }
        CryptographicOperations.ZeroMemory(frame); length = 0; awaitingAcknowledgement = false;
    }
    public void Dispose() { CryptographicOperations.ZeroMemory(frame); consumed.Clear(); invalidated = true; }
}
