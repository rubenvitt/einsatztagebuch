using System.Text;
using System.Text.Json;
using Ea.NativeOperator;

internal static class WatchChallengeTests
{
    internal static void Run(Action<bool, string> check)
    {
        string nonce = new('b', 64), id = new('a', 64);
        byte[] Frame(string challenge) => Encoding.ASCII.GetBytes("{\"challenge\":\"" + challenge + "\"}\n");
        void Reject(WatchChallenges parser, byte[] bytes)
        {
            try { parser.Append(bytes); throw new Exception("watch frame accepted"); }
            catch (Failure failure) { check(failure.Code == "watch-invalidated", "malformed/replayed watch input invalidates"); }
        }
        using (var parser = new WatchChallenges())
        {
            var frame = Frame(nonce);
            for (int i = 0; i < frame.Length - 1; i++)
                if (parser.Append(frame.AsSpan(i, 1)) != null) throw new Exception("partial challenge acknowledged");
            check(parser.Append(frame.AsSpan(frame.Length - 1)) == nonce, "fragmented challenge emits only after LF");
            parser.Acknowledged();
            check(parser.Append(Frame(id)) == id, "fresh challenge after completed ACK accepted");
            parser.Acknowledged();
            Reject(parser, Frame(nonce)); // older than the most recent nonce
            Reject(parser, Frame(new string('c', 64))); // invalidation irreversible
        }
        foreach (string text in new[] {
            "{}\n", "{\"nonce\":\"" + nonce + "\"}\n", "{\"challenge\":null}\n", "{\"challenge\":123}\n",
            "{\"challenge\":\"" + nonce + "\",\"ready\":true}\n",
            "{\"challenge\":\"" + nonce + "\",\"challenge\":\"" + nonce + "\"}\n",
            "{\"challenge\":\"" + nonce + "\",\"\\u0063hallenge\":\"" + nonce + "\"}\n",
            "{\"challenge\":\"" + new string('B', 64) + "\"}\n",
            "{\"challenge\":\"" + new string('a', 63) + "\"}\n",
            "{\"challenge\":\"" + new string('a', 65) + "\"}\n",
            "{\"challenge\":\"\\u0062" + new string('b', 63) + "\"}\n",
            "{\"challenge\":[]}\n", "{\"challenge\":\"" + nonce + "\"}{}\n", "\n"
        }) { using var parser = new WatchChallenges(); Reject(parser, Encoding.UTF8.GetBytes(text)); }
        using (var parser = new WatchChallenges()) Reject(parser, [0xff, 10]);
        using (var parser = new WatchChallenges()) Reject(parser, Frame(nonce).Concat(Frame(id)).ToArray());
        using (var parser = new WatchChallenges())
        {
            _ = parser.Append(Frame(nonce));
            Reject(parser, Frame(id)); // second outstanding before acknowledgement
        }
        using (var parser = new WatchChallenges())
        {
            byte[] frame = Frame(nonce);
            byte[] maximum = Encoding.ASCII.GetBytes(new string(' ', 1024 - frame.Length)).Concat(frame).ToArray();
            check(parser.Append(maximum) == nonce, "1024-byte challenge frame including LF accepted");
        }
        using (var parser = new WatchChallenges()) Reject(parser, new byte[1025]);
        using (var parser = new WatchChallenges())
        {
            check(parser.Append(Encoding.ASCII.GetBytes(new string(' ', 1023))) == null, "partial frame buffer remains bounded");
            Reject(parser, Encoding.ASCII.GetBytes(" \n"));
        }
        using (var parser = new WatchChallenges())
        {
            bool valid = true;
            for (int i = 0; i < WatchChallenges.MaximumChallenges; i++)
            {
                string fresh = i.ToString("x64");
                valid &= parser.Append(Frame(fresh)) == fresh; parser.Acknowledged();
            }
            check(valid, "bounded replay history accepts distinct nonces");
            Reject(parser, Frame(WatchChallenges.MaximumChallenges.ToString("x64")));
        }
        byte[] ack = Transport.WatchAcknowledgement(id, nonce);
        using (var json = JsonDocument.Parse(ack))
            check(json.RootElement.EnumerateObject().Count() == 3 && json.RootElement.GetProperty("ok").GetBoolean() &&
                json.RootElement.GetProperty("installation_id").GetString() == id && json.RootElement.GetProperty("challenge").GetString() == nonce,
                "closed ACK echoes exact installation and fresh challenge");
        using var output = new MemoryStream();
        Transport.WriteLine(output, ack);
        check(output.Length <= 1024 && output.ToArray()[^1] == 10 && ack.All(b => b == 0), "ACK is bounded, LF-terminated and owned buffer cleared");
    }
}
