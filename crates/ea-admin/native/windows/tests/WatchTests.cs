using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Ea.NativeOperator;

internal static class WatchTests
{
    internal static async Task Run(Action<bool, string> check)
    {
        string id = new('a', 64);
        string request = "{\"op\":\"watch-session\",\"installation_id\":\"" + id + "\"}";
        foreach (string field in new[] { "\"presence\":false", "\"timeout_ms\":1", "\"slot\":\"database-key\"", "\"ready\":true", "\"prompt\":\"display-name\"", "\"installation_id\":\"" + id + "\"" })
        {
            try { using var invalid = Request.Parse(Encoding.UTF8.GetBytes(request[..^1] + "," + field + "}")); throw new Exception("watch accepted additional field"); }
            catch (Failure error) { check(error.Code == "invalid-request", "watch has only op and installation_id"); }
        }
        try { using var invalid = Request.Parse("{\"op\":\"watch-session\"}"u8); throw new Exception("unpinned watch"); }
        catch (Failure error) { check(error.Code == "installation-required", "watch pin mandatory"); }
        // Real production framing over a deliberately chunked, still-open input.
        // This is a transport stream, not a substitute native account/provider.
        using (var stream = new ChunkStream())
        {
            var read = Transport.ReadAsync(stream);
            stream.Send(request[..20]);
            await stream.WaitRead();
            check(!read.IsCompleted, "partial watcher JSON does not dispatch");
            stream.Send(request[20..]);
            await stream.WaitRead();
            check(!read.IsCompleted, "watch JSON without newline waits");
            stream.Send("\n");
            using var frame = await read.WaitAsync(TimeSpan.FromSeconds(2));
            check(frame.Watch && Encoding.UTF8.GetString(frame.Bytes) == request && !stream.Closed, "watch line dispatches with stdin open");
        }
        using (var stream = new ChunkStream())
        {
            var read = Transport.ReadAsync(stream);
            stream.Send("{\"op\":\"account\"}\n");
            await stream.WaitRead();
            check(!read.IsCompleted, "ordinary newline does not replace EOF framing");
            stream.CloseInput();
            using var frame = await read.WaitAsync(TimeSpan.FromSeconds(2));
            check(!frame.Watch, "ordinary request dispatches on EOF only");
        }
        using (var frame = await Transport.ReadAsync(new MemoryStream(Encoding.UTF8.GetBytes(request))))
            check(!frame.Watch, "watch without newline is not a watch frame; entrypoint rejects it");
        using (var frame = await Transport.ReadAsync(new MemoryStream(Encoding.UTF8.GetBytes(request + "\r\n"))))
            check(frame.Watch, "CRLF watcher frame accepted");
        foreach (string suffix in new[] { "{}", " ", "\n" })
        {
            try { using var frame = await Transport.ReadAsync(new MemoryStream(Encoding.UTF8.GetBytes(request + "\n" + suffix))); throw new Exception("trailing watch input accepted"); }
            catch (Failure error) { check(error.Code == "invalid-request", "already buffered post-line input rejected"); }
        }
        var lifetime = new WatchLifetime();
        check(lifetime.Continue(0, true) && !lifetime.Continue(1001, true), "a stopped watcher invalidates before acknowledging a resumed challenge");
        lifetime = new WatchLifetime();
        bool continuous = true;
        for (long now = 0; now <= 299_000; now += 1_000) continuous &= lifetime.Continue(now, true);
        check(continuous && lifetime.Continue(299_999, true), "continuous observations permit watch only before fixed five-minute limit");
        check(!lifetime.Continue(300_000, true) && !lifetime.Continue(1, true), "expiry is terminal even if clock/state is reset by caller");
        lifetime = new WatchLifetime();
        check(!lifetime.Continue(10, false) && !lifetime.Continue(11, true), "short lock/unlock cannot revive watch");
        lifetime = new WatchLifetime();
        check(lifetime.Continue(0, true) && lifetime.CanObserve(999) && !lifetime.CanObserve(1001) && !lifetime.Continue(1002, true), "time/input checks do not renew native coverage and a gap cannot be erased");
        lifetime = new WatchLifetime();
        check(lifetime.Continue(100, true) && !lifetime.Continue(99, true), "regressing coverage clock invalidates");
        WatchChallengeTests.Run(check);
        foreach (nuint kind in new nuint[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15 })
            check(WatchLifetime.SessionChangeInvalidates(4, 4, kind) && !WatchLifetime.SessionChangeInvalidates(4, 5, kind), "all documented current-session transitions latch, other session ignored");
        check(!WatchLifetime.SessionChangeInvalidates(4, 4, 0), "unrelated message is not WTS transition");
        using var output = new MemoryStream();
        foreach (bool ready in new[] { true, false })
        {
            var response = Transport.WatchReply(id, ready);
            using var parsed = JsonDocument.Parse(response);
            check(parsed.RootElement.EnumerateObject().Count() == 3 && parsed.RootElement.GetProperty("ok").GetBoolean() &&
                parsed.RootElement.GetProperty("installation_id").GetString() == id && parsed.RootElement.GetProperty(ready ? "ready" : "invalidated").GetBoolean(), "closed watch event echoes public pin only");
            Transport.WriteLine(output, response);
            check(response.All(b => b == 0), "watch write clears owned response");
        }
        string written = Encoding.UTF8.GetString(output.ToArray());
        check(written.Count(c => c == '\n') == 2 && written.EndsWith('\n'), "watch emits exactly two newline-delimited records");
        check(Marshal.SizeOf<Win32.FilePipeLocalInformation>() == 40 && Marshal.OffsetOf<Win32.FilePipeLocalInformation>("NamedPipeState").ToInt32() == 32 &&
            Marshal.SizeOf<Win32.IoStatusBlock>() == 16, "x64/ARM64 native pipe-state ABI");
    }

    private sealed class ChunkStream : Stream
    {
        private readonly Channel<byte[]> chunks = Channel.CreateUnbounded<byte[]>();
        private readonly Channel<bool> consumed = Channel.CreateUnbounded<bool>();
        internal bool Closed { get; private set; }
        internal void Send(string chunk) => chunks.Writer.TryWrite(Encoding.UTF8.GetBytes(chunk));
        internal Task WaitRead() => consumed.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(2));
        internal void CloseInput() { Closed = true; chunks.Writer.TryComplete(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!await chunks.Reader.WaitToReadAsync(cancellationToken)) return 0;
            byte[] chunk = await chunks.Reader.ReadAsync(cancellationToken);
            chunk.AsSpan().CopyTo(buffer.Span); consumed.Writer.TryWrite(true); return chunk.Length;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
