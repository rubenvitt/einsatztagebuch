using System.Diagnostics;

namespace Ea.NativeOperator;

internal static class SessionWatch
{
    internal static int Run(Request request, Stream output, out bool readyAttempted)
    {
        readyAttempted = false;
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) || !Environment.Is64BitProcess) throw new Failure("platform-unavailable");
        NativeProvider.RequireParentPipes();
        using var account = new NativeAccount();
        using var parent = new ParentLifetime(account);
        // Registration happens BEFORE installation observation and ready. The
        // STA thread pumps this same window continuously until final exit.
        var clock = Stopwatch.StartNew();
        var lifetime = new WatchLifetime();
        using var session = new SessionWindow(account);
        Installation.Observation observation;
        string id;
        using (var installation = new Installation(account, false))
        {
            if (!installation.Load()) throw new Failure("installation-missing");
            installation.RequireExpected(request.InstallationId);
            installation.Recheck(); session.RequireUnlocked(); parent.Recheck();
            id = installation.IdHex;
            observation = installation.Observe();
        } // release exclusive gate/marker; zero the secret wrapping key
        using (observation)
        {
            void Recheck()
            {
                if (!lifetime.CanObserve(clock.ElapsedMilliseconds)) throw new Failure("watch-invalidated");
                parent.Recheck(); session.RequireUnlocked(); observation.Recheck();
                // Drain again after filesystem/registry/account work. Coverage
                // renews only after this native event-loop observation succeeds.
                session.RequireUnlocked(); parent.Recheck();
                if (!lifetime.Continue(clock.ElapsedMilliseconds, true)) throw new Failure("watch-invalidated");
            }
            Recheck(); // read-only marker checks, after releasing the operation gate
            if (parent.AvailableInput() != 0) throw new Failure("watch-invalidated"); // no pre-ready challenges
            var ready = Transport.WatchReply(id, true);
            parent.RequireWritable(ready.Length + 1);
            if (!lifetime.CanObserve(clock.ElapsedMilliseconds)) throw new Failure("watch-invalidated");
            // Once we attempt ready, no later failure may become a third/error
            // record. Output failure terminates, which the parent must latch.
            readyAttempted = true;
            try { Transport.WriteLine(output, ready); }
            catch { return 1; }
            using var challenges = new WatchChallenges();
            Span<byte> input = stackalloc byte[WatchChallenges.MaximumFrameBytes];
            while (true)
            {
                try
                {
                    Recheck();
                    int read = parent.ReadInput(input);
                    if (read != 0)
                    {
                        string? challenge = challenges.Append(input[..read]);
                        if (challenge != null)
                        {
                            Recheck(); // ACK is never emitted by a reader/worker thread
                            if (parent.AvailableInput() != 0) throw new Failure("watch-invalidated");
                            var acknowledgement = Transport.WatchAcknowledgement(id, challenge);
                            parent.RequireWritable(acknowledgement.Length + 1);
                            if (!lifetime.CanObserve(clock.ElapsedMilliseconds)) throw new Failure("watch-invalidated");
                            Transport.WriteLine(output, acknowledgement);
                            challenges.Acknowledged();
                        }
                    }
                }
                catch { lifetime.Continue(clock.ElapsedMilliseconds, false); break; }
                finally { input.Clear(); }
                Thread.Sleep((int)Math.Min(50, Math.Max(0, WatchLifetime.MaximumMilliseconds - clock.ElapsedMilliseconds)));
            }
            // Expiry, EOF, lock/unlock, account/marker change and observation
            // errors all end this instance permanently. No automatic restart.
            try
            {
                var invalidated = Transport.WatchReply(id, false);
                parent.RequireWritable(invalidated.Length + 1);
                Transport.WriteLine(output, invalidated);
                return 0;
            }
            catch { return 1; }
        }
    }
}
