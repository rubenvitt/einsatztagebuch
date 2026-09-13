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
        bool signingBackup = false;
        byte[]? pendingSigningBackup = null;
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
            signingBackup = request.Op == "backup-signing-seed";
            response = NativeProvider.Execute(request);
            if (signingBackup) pendingSigningBackup = response;
            success = true;
        }
        catch (Exception error)
        {
            // Even a disposal failure after streaming readiness must terminate,
            // never append an ordinary/third error record to a watcher stream.
            if (watchReadyAttempted) return 1;
            if (pendingSigningBackup != null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(pendingSigningBackup);
            response = Transport.Error(error);
        }
        try
        {
            using var output = Console.OpenStandardOutput();
            if (success && signingBackup) Transport.WriteSigningBackup(output, response);
            else Transport.WriteLine(output, response);
            return success ? 0 : 1;
        }
        catch { return 1; }
        finally { if (pendingSigningBackup != null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(pendingSigningBackup); }
    }
}
