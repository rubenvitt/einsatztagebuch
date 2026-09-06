namespace Ea.NativeOperator;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        // No diagnostic exception strings, account names, payloads or traces on
        // either stream. Parsing can be exercised on any host without native APIs.
        byte[] response;
        bool success = false;
        bool watchReadyAttempted = false;
        try
        {
            if (args.Length != 0) throw new Failure("invalid-request");
            using var input = Console.OpenStandardInput();
            using var frame = Transport.ReadAsync(input).GetAwaiter().GetResult();
            using var request = Request.Parse(frame.Bytes);
            if ((request.Op == "watch-session") != frame.Watch) throw new Failure("invalid-request");
            if (frame.Watch)
            {
                using var watchOutput = Console.OpenStandardOutput();
                return SessionWatch.Run(request, watchOutput, out watchReadyAttempted);
            }
            response = NativeProvider.Execute(request);
            success = true;
        }
        catch (Exception error)
        {
            // Even a disposal failure after streaming readiness must terminate,
            // never append an ordinary/third error record to a watcher stream.
            if (watchReadyAttempted) return 1;
            response = Transport.Error(error);
        }
        try
        {
            using var output = Console.OpenStandardOutput();
            Transport.WriteLine(output, response);
            return success ? 0 : 1;
        }
        catch { return 1; }
    }
}
