#if SELF_TEST || WATCH_STATE_TEST
import Foundation
import Darwin

enum WatchTests {
    static func standalone() throws {
        var count = 0
        func check(_ condition: () throws -> Bool) throws {
            guard try condition() else { throw Failure("watch-test-\(count + 1)") }
            count += 1
        }
        func rejects(_ expected: String, _ body: () throws -> Void) throws {
            do { try body(); throw Failure("unexpected-success") }
            catch let failure as Failure { try check { failure.code == expected } }
        }
        try run(check: check, rejects: rejects)
        print("{\"ok\":true,\"watch_state_tests\":\(count)}")
    }
    static func run(check: ((() throws -> Bool)) throws -> Void,
                    rejects: (String, () throws -> Void) throws -> Void) throws {
        let id = String(repeating: "ab", count: 32)
        let request = try Request.parse(Data("{\"op\":\"watch-session\",\"installation_id\":\"\(id)\"}".utf8))
        try check { request.op == "watch-session" && request.expectedInstallationID?.count == 32 }
        for suffix in ["", ",\"presence\":true", ",\"slot\":\"writer-signing\"", ",\"timeout\":true"] {
            let fields = suffix.isEmpty ? "" : ",\"installation_id\":\"\(id)\"" + suffix
            try rejects("invalid-request") {
                _ = try Request.parse(Data("{\"op\":\"watch-session\"\(fields)}".utf8))
            }
        }
        let latch = WatchLatch()
        try check { !latch.invalidated }
        latch.invalidate(); latch.invalidate()
        try check { latch.invalidated }
        try rejects("code-identity-invalid") { _ = try CodeIdentity.ownTeam(identifier: CodeIdentity.helper) }
        let account = try NativeAccount.validate(guidValues: ["12345678-1234-4234-8234-123456789abc"], uniqueIDValues: [String(getuid())], uid: getuid())
        let other = try NativeAccount.validate(guidValues: ["22345678-1234-4234-8234-123456789abc"], uniqueIDValues: [String(getuid())], uid: getuid())
        var guardState = WatchAccountGuard()
        try rejects("busy") { try guardState.check(account: account, active: true) { throw Failure("busy") } }
        try guardState.check(account: account, active: true) { true }
        try guardState.check(account: account, active: true) { throw Failure("busy") }
        try check { true } // an in-progress native presence call does not abort the watch
        try rejects("account-changed") { try guardState.check(account: other, active: true) { throw Failure("busy") } }
        try rejects("account-changed") { try guardState.check(account: account, active: false) { true } }
        try rejects("locked") { try guardState.check(account: account, active: true) { false } }
        try rejects("installation-changed") { try guardState.check(account: account, active: true) { throw Failure("installation-changed") } }
        let nonce = String(repeating: "ab", count: 32)
        try check { try Request.parseChallenge(Data("{\"challenge\":\"\(nonce)\"}".utf8)) == nonce }
        for text in ["{}", "[]", "{\"challenge\":true}", "{\"challenge\":null}",
                     "{\"challenge\":\"\(nonce.uppercased())\"}", "{\"challenge\":\"ab\"}",
                     "{\"challenge\":\"\(nonce)\",\"extra\":false}",
                     "{\"challenge\":\"\(nonce)\",\"challenge\":\"\(nonce)\"}",
                     "{\"challenge\":\"\(nonce)\",\"chall\\u0065nge\":\"\(nonce)\"}",
                     "{\"challenge\":\"\(nonce)\"} {}", String(repeating: " ", count: 1024)] {
            try rejects("invalid-request") { _ = try Request.parseChallenge(Data(text.utf8)) }
        }
        try monitorTests(check: check)
        try connectionTests(check: check, rejects: rejects)
    }

    static func monitorTests(check: ((() throws -> Bool)) throws -> Void) throws {
        func pair() throws -> [Int32] {
            var descriptors: [Int32] = [-1, -1]
            guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else { throw Failure("self-test-socket") }
            try MonitorSocket.nonblocking(descriptors[0]); try MonitorSocket.nonblocking(descriptors[1])
            return descriptors
        }
        func read(_ fd: Int32) -> String {
            var bytes = [UInt8](repeating: 0, count: 128)
            let count = Darwin.read(fd, &bytes, bytes.count)
            return count <= 0 ? "" : String(decoding: bytes.prefix(count), as: UTF8.self)
        }
        let ready = String(decoding: MonitorFrame.encode(82, generatedAt: 0), as: UTF8.self)
        let heartbeat = String(decoding: MonitorFrame.encode(72, generatedAt: 0), as: UTF8.self)
        let state = MonitorState()
        let first = try pair()
        defer { close(first[1]) }
        try check { !state.add(first[0], now: 0) } // uncertain startup
        state.event(sequence: 100, version: 4, unlock: nil, heartbeat: true, now: 0)
        state.event(sequence: 101, version: 4, unlock: true, now: 0)
        try check { state.add(first[0], now: 0) }
        try check { read(first[1]) == ready }
        state.event(sequence: 102, version: 4, unlock: false, now: 0)
        state.event(sequence: 103, version: 4, unlock: true, now: 0)
        try check { read(first[1]) == "I\n" } // whole lock/unlock remains latched
        let second = try pair()
        defer { close(second[1]) }
        try check { state.add(second[0], now: 0) }
        try check { read(second[1]) == ready }
        state.event(sequence: 105, version: 4, unlock: true, now: 0) // missing sequence 104
        try check { read(second[1]) == "I\n" }
        let denied = try pair()
        defer { close(denied[0]); close(denied[1]) }
        state.event(sequence: 106, version: 4, unlock: true, now: 0)
        try check { !state.add(denied[0], now: 0) } // coverage never recovers

        let limited = MonitorState()
        limited.event(sequence: 0, version: 4, unlock: nil, heartbeat: true, now: 0)
        limited.event(sequence: 1, version: 4, unlock: true, now: 0)
        var readers: [Int32] = []
        defer { readers.forEach { close($0) }; limited.loseCoverage() }
        for _ in 0..<MonitorState.maximumClients {
            let descriptors = try pair(); readers.append(descriptors[1])
            try check { limited.add(descriptors[0], now: 0) }
            try check { read(descriptors[1]) == ready }
        }
        try check { !limited.add(denied[0], now: 0) }
        limited.tick(now: 300)
        try check { readers.allSatisfy { read($0) == "I\n" } }
        let oldMessage = MonitorState()
        oldMessage.event(sequence: 0, version: 3, unlock: true, now: 0)
        try check { !oldMessage.add(denied[0], now: 0) }
        let noHeartbeat = MonitorState()
        noHeartbeat.event(sequence: 0, version: 4, unlock: true, now: 0)
        try check { !noHeartbeat.add(denied[0], now: 0) }
        let lostHeartbeat = MonitorState()
        lostHeartbeat.event(sequence: 0, version: 4, unlock: nil, heartbeat: true, now: 0)
        lostHeartbeat.event(sequence: 1, version: 4, unlock: true, now: 0)
        lostHeartbeat.tick(now: 1)
        lostHeartbeat.event(sequence: 2, version: 4, unlock: nil, heartbeat: true, now: 1)
        try check { !lostHeartbeat.add(denied[0], now: 1) }

        func active() throws -> (MonitorState, Int32) {
            let state = MonitorState()
            let descriptors = try pair()
            state.event(sequence: 0, version: 4, unlock: nil, heartbeat: true, now: 0)
            state.event(sequence: 1, version: 4, unlock: true, now: 0)
            try check { state.add(descriptors[0], now: 0) }
            try check { read(descriptors[1]) == ready }
            return (state, descriptors[1])
        }
        let (paced, pacedReader) = try active()
        defer { paced.loseCoverage(); close(pacedReader) }
        for step in 1...40 { paced.tick(now: Double(step) / 1000) }
        try check { read(pacedReader) == heartbeat } // only one broadcast, not forty
        paced.tick(now: 0.2)
        try check { read(pacedReader) == heartbeat } // transmit time cannot renew evidence
        paced.event(sequence: 2, version: 4, unlock: nil, heartbeat: true, now: 0.4, generatedAt: 0.3)
        paced.tick(now: 0.4)
        try check { read(pacedReader) == String(decoding: MonitorFrame.encode(72, generatedAt: 0.3), as: UTF8.self) }

        let (lateCallback, lateReader) = try active()
        defer { lateCallback.loseCoverage(); close(lateReader) }
        lateCallback.tick(now: 0.9)
        try check { read(lateReader) == heartbeat }
        lateCallback.event(sequence: 2, version: 4, unlock: nil, heartbeat: true, now: 1.05)
        lateCallback.tick(now: 1.1)
        try check { read(lateReader) == "I\n" }
        lateCallback.event(sequence: 3, version: 4, unlock: true, heartbeat: true, now: 1.2)
        try check { !lateCallback.add(denied[0], now: 1.2) }

        let (lateAdmission, admissionReader) = try active()
        defer { lateAdmission.loseCoverage(); close(admissionReader) }
        try check { !lateAdmission.add(denied[0], now: 1) }
        try check { read(admissionReader) == "I\n" }
        lateAdmission.event(sequence: 2, version: 4, unlock: true, heartbeat: true, now: 1.1)
        try check { !lateAdmission.add(denied[0], now: 1.1) }

        let (delayedEvent, delayedReader) = try active()
        defer { delayedEvent.loseCoverage(); close(delayedReader) }
        delayedEvent.event(sequence: 2, version: 4, unlock: true, now: 0.5, generatedAt: -0.6)
        try check { read(delayedReader) == "I\n" }
        let delayedStart = MonitorState()
        delayedStart.event(sequence: 0, version: 4, unlock: true, heartbeat: true, now: 10, generatedAt: 8.9)
        try check { !delayedStart.add(denied[0], now: 10) }
    }

    static func connectionTests(check: ((() throws -> Bool)) throws -> Void,
                                rejects: (String, () throws -> Void) throws -> Void) throws {
        func send(_ fd: Int32, _ bytes: [UInt8]) throws {
            guard bytes.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress!, $0.count) }) == bytes.count else {
                throw Failure("self-test-socket")
            }
        }
        for mode in ["fresh", "queued-I", "queued-EOF", "over-budget", "stale", "future", "backwards",
                     "duplicate-ready", "partial", "old-wire", "malformed"] {
            var descriptors: [Int32] = [-1, -1]
            guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else { throw Failure("self-test-socket") }
            try MonitorSocket.nonblocking(descriptors[0]); try MonitorSocket.nonblocking(descriptors[1])
            defer { if descriptors[1] >= 0 { close(descriptors[1]) } }
            let generated = WatchClock.now() - 0.05
            try send(descriptors[1], MonitorFrame.encode(82, generatedAt: generated))
            let connection = try MonitorConnection(fixtureSocket: descriptors[0])
            try connection.check()
            let fresh = MonitorFrame.encode(72, generatedAt: generated)
            switch mode {
            case "fresh": try send(descriptors[1], fresh)
            case "queued-I": try send(descriptors[1], Array(repeating: fresh, count: 40).flatMap { $0 } + [73, 10])
            case "queued-EOF":
                try send(descriptors[1], Array(repeating: fresh, count: 40).flatMap { $0 })
                close(descriptors[1]); descriptors[1] = -1
            case "over-budget": try send(descriptors[1], Array(repeating: fresh, count: 60).flatMap { $0 })
            case "stale": try send(descriptors[1], MonitorFrame.encode(72, generatedAt: generated - 2))
            case "future": try send(descriptors[1], MonitorFrame.encode(72, generatedAt: generated + 5))
            case "backwards": try send(descriptors[1], MonitorFrame.encode(72, generatedAt: generated - 0.01))
            case "duplicate-ready": try send(descriptors[1], MonitorFrame.encode(82, generatedAt: generated))
            case "partial": try send(descriptors[1], Array(fresh.dropLast()))
            case "old-wire": try send(descriptors[1], [72, 10])
            default: try send(descriptors[1], [72] + Array(repeating: 65, count: 16) + [10])
            }
            if mode == "fresh" { try connection.check(); try check { true } }
            else {
                try rejects("watch-unavailable") { try connection.check() }
                try rejects("watch-unavailable") { try connection.check() } // never recover
            }
        }
    }
}
#endif

#if WATCH_TEST
import Foundation

// A separate executable only; production arguments/environment never select it.
final class FixtureWatchEvents: WatchEvents {
    let mode: String
    private var latch: WatchLatch?
    private var checks = 0
    private var subscribed = false
    init(mode: String) { self.mode = mode }
    func subscribe(_ latch: WatchLatch) throws { self.latch = latch; subscribed = true }
    func requireCoverage() throws {
        guard subscribed, mode != "uncertain" else { throw Failure("watch-unavailable") }
        if mode == "startup-event" { latch?.invalidate() }
    }
    func checkCoverage() throws {
        checks += 1
        if checks == 3 && mode == "lock-unlock" { latch?.invalidate(); latch?.invalidate() }
        if checks == 3 && mode == "lost" { throw Failure("watch-unavailable") }
        if checks == 2 && mode == "stalled-native" { awaitChallenge() }
        if checks == 3 && mode == "stalled-native" { stall() }
        if checks == 3 && mode == "lock-on-challenge" { latch?.invalidate() }
    }
    // Check 2 is the first loop drain after readiness. Holding it until the
    // challenge bytes are queued makes check 3 the drain inside the challenge
    // branch, i.e. the one that runs before any acknowledgement.
    private func awaitChallenge() {
        var input = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
        _ = poll(&input, 1, 5_000)
    }
    // The test observes the stall on the barrier, checks that nothing was
    // acknowledged, and releases it. The stall then lasts at least 1.1 s on
    // the session's own clock, so it always exceeds the one-second budget.
    private func stall() {
        let started = WatchClock.now()
        guard let text = ProcessInfo.processInfo.environment["EA_WATCH_BARRIER_FD"],
              let barrier = Int32(text) else { return }
        var byte: UInt8 = 83 // "S"
        guard Darwin.write(barrier, &byte, 1) == 1, Darwin.read(barrier, &byte, 1) == 1 else { return }
        while WatchClock.now() - started < 1.1 { Thread.sleep(forTimeInterval: 0.05) }
    }
    func cancel() { latch = nil }
}

enum WatchFixture {
    static func run() throws {
        let request = try Request.parse(Transport.readRequest())
        try Transport.requirePrivatePipes()
        guard request.op == "watch-session", let id = request.expectedInstallationID,
              CommandLine.arguments.count == 2 else { throw Failure("invalid-request") }
        let mode = CommandLine.arguments[1]
        let events = FixtureWatchEvents(mode: mode)
        try WatchSession(events: events, checkAccount: {
            if mode == "locked" { throw Failure("locked") }
        }, seconds: mode == "expiry" ? 0.08 : (mode == "challenge-expiry" ? 0.6 : 2)).run(installationID: id)
    }
}
#endif
