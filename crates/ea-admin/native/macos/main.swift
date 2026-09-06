import Foundation
import Darwin

// The helper writes no diagnostic text, account name, error description or key.
// Suppress core files; Swift/CryptoKit memory is not claimed immune to swapping
// or privileged debugging. The signed parent owns the private IPC endpoints.
signal(SIGPIPE, SIG_IGN)
var coreLimit = rlimit(rlim_cur: 0, rlim_max: 0)
do {
    guard setrlimit(RLIMIT_CORE, &coreLimit) == 0 else { throw Failure("io-failed") }
    #if MONITOR_DAEMON
    guard CommandLine.arguments.count == 1 else { throw Failure("invalid-request") }
    try MonitorDaemon.run()
    #elseif WATCH_STATE_TEST
    try WatchTests.standalone()
    #elseif WATCH_TEST
    try WatchFixture.run()
    #elseif NATIVE_READ_ONLY_TEST
    try NativeReadOnlyTests.run()
    #elseif SELF_TEST
    try SelfTests.run()
    #else
    // Independent process ceiling also covers blocked OS calls / partial input.
    alarm(300)
    guard CommandLine.arguments.count == 1 else { throw Failure("invalid-request") }
    let bytes = try Transport.readRequest()
    let request = try Request.parse(bytes)
    try Transport.requirePrivatePipes()
    if request.op == "watch-session", let id = request.expectedInstallationID {
        try WatchSession(request: request).run(installationID: id)
    } else {
        Transport.writeResponse(try NativeProvider().execute(request))
    }
    #endif
} catch let failure as Failure {
    Transport.writeResponse(["ok": false, "code": failure.code])
    exit(1)
} catch {
    Transport.writeResponse(["ok": false, "code": "native-failed"])
    exit(1)
}
