namespace Ea.NativeOperator;

// Used by the native window procedure and the persistent watch loop. No test
// provider or synthetic clock can be selected by an IPC request/environment.
internal sealed class WatchLifetime
{
    internal const int MaximumMilliseconds = 300_000;
    internal const int MaximumCoverageGapMilliseconds = 1_000;
    private bool invalidated;
    private long lastObservation;
    // Checking time does not renew coverage. Only a completed native event/state
    // observation can advance lastObservation; queued input cannot keep us alive.
    internal bool CanObserve(long elapsedMilliseconds)
    {
        invalidated |= elapsedMilliseconds < lastObservation || elapsedMilliseconds >= MaximumMilliseconds ||
            elapsedMilliseconds - lastObservation > MaximumCoverageGapMilliseconds;
        return !invalidated;
    }
    internal bool Continue(long elapsedMilliseconds, bool healthy)
    {
        invalidated |= !healthy;
        if (CanObserve(elapsedMilliseconds)) lastObservation = elapsedMilliseconds;
        return !invalidated;
    }
    internal static bool SessionChangeInvalidates(uint expectedSession, uint eventSession, nuint kind) =>
        eventSession == expectedSession && (kind is >= 1 and <= 11 or 15);
}
