import Foundation
import AppKit
import Darwin
import notify

private enum WatchInput {
    case idle, disconnected, challenge(String)
}

private struct WatchChallenges {
    private var bytes = Data()
    private var started: TimeInterval?
    private var used: Set<String> = []

    mutating func read(_ fd: Int32, now: TimeInterval) throws -> WatchInput {
        if let started, now - started >= 1 { throw Failure("invalid-request") }
        // A second outstanding frame, trailing byte, huge input, or a stream
        // that exhausts the read budget is terminal before any acknowledgement.
        for _ in 0..<32 {
            var buffer = [UInt8](repeating: 0, count: 1025 - bytes.count)
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count == 0 { return .disconnected }
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                guard let newline = bytes.firstIndex(of: 10) else { return .idle }
                guard newline == bytes.count - 1, used.count < 16_384 else { throw Failure("invalid-request") }
                let nonce = try Request.parseChallenge(Data(bytes[..<newline]))
                guard used.insert(nonce).inserted else { throw Failure("invalid-request") }
                bytes.removeAll(keepingCapacity: true); started = nil
                return .challenge(nonce)
            }
            guard count > 0 else { throw Failure("io-failed") }
            if started == nil { started = now }
            bytes.append(contentsOf: buffer.prefix(count))
            guard bytes.count <= 1024 else { throw Failure("invalid-request") }
            if let newline = bytes.firstIndex(of: 10), newline != bytes.count - 1 { throw Failure("invalid-request") }
        }
        throw Failure("invalid-request")
    }
}

// Monotonic latch shared by synchronous native callbacks and the run loop.
// No callback, including unlock, can restore readiness.
final class WatchLatch: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func invalidate() { lock.lock(); value = true; lock.unlock() }
    var invalidated: Bool { lock.lock(); defer { lock.unlock() }; return value }
}

protocol WatchEvents: AnyObject {
    func subscribe(_ latch: WatchLatch) throws
    func requireCoverage() throws
    func checkCoverage() throws
    func cancel()
}

struct WatchAccountGuard {
    private var bound: NativeAccount?
    mutating func check(account: NativeAccount, active: Bool, snapshot: () throws -> Bool) throws {
        guard active, bound == nil || bound == account else { throw Failure("account-changed") }
        do {
            guard try snapshot() else { throw Failure("locked") }
        } catch let failure as Failure where failure.code == "busy" && bound != nil {
            // A presence/signing helper holds the marker flock across LA.
            // Preserve ES/account monitoring during that operation. Never skip
            // an initial snapshot or a locked/invalid/missing namespace result.
            return
        }
        bound = account
    }
}

// DNC and NSWorkspace supplement the authenticated EndpointSecurity service.
// They never establish authoritative readiness on their own.
final class WorkspaceWatchEvents: NSObject, WatchEvents, @unchecked Sendable {
    private var latch: WatchLatch?
    private var workspaceTokens: [NSObjectProtocol] = []
    private var directoryToken: Int32 = -1
    private let monitor = MonitorConnection()
    private let distributedLatch = WatchLatch()

    func subscribe(_ latch: WatchLatch) throws {
        guard Thread.isMainThread else { throw Failure("watch-unavailable") }
        self.latch = latch
        let center = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.sessionDidResignActiveNotification,
                     NSWorkspace.sessionDidBecomeActiveNotification,
                     NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification,
                     NSWorkspace.screensDidSleepNotification, NSWorkspace.willPowerOffNotification] {
            workspaceTokens.append(center.addObserver(forName: name, object: nil, queue: nil) { _ in latch.invalidate() })
        }
        for name in ["com.apple.screenIsLocked", "com.apple.screenIsUnlocked"] {
            DistributedNotificationCenter.default().addObserver(self, selector: #selector(changed(_:)),
                name: Notification.Name(name), object: nil, suspensionBehavior: .deliverImmediately)
        }
        // The documented DirectoryService cache event is conservative: any
        // user record invalidation terminates the watch, even if unrelated.
        guard notify_register_check("com.apple.system.DirectoryService.InvalidateCache.user", &directoryToken) == NOTIFY_STATUS_OK else {
            throw Failure("watch-unavailable")
        }
        var initial: Int32 = 0
        guard notify_check(directoryToken, &initial) == NOTIFY_STATUS_OK else { throw Failure("watch-unavailable") }
    }

    @objc private func changed(_ notification: Notification) { distributedLatch.invalidate() }

    func requireCoverage() throws {
        try monitor.connect()
    }

    func checkCoverage() throws {
        try monitor.check()
        if distributedLatch.invalidated { latch?.invalidate() }
        var changed: Int32 = 0
        guard directoryToken >= 0, notify_check(directoryToken, &changed) == NOTIFY_STATUS_OK else {
            throw Failure("watch-unavailable")
        }
        if changed != 0 { latch?.invalidate() }
    }

    func cancel() {
        monitor.close()
        for token in workspaceTokens { NSWorkspace.shared.notificationCenter.removeObserver(token) }
        workspaceTokens.removeAll()
        DistributedNotificationCenter.default().removeObserver(self)
        if directoryToken >= 0 { notify_cancel(directoryToken); directoryToken = -1 }
        latch = nil
    }
    deinit { cancel() }
}

final class WatchSession {
    static let maximumSeconds: TimeInterval = 300
    private let events: any WatchEvents
    private let checkAccount: () throws -> Void
    private let input: Int32
    private let output: Int32
    private let seconds: TimeInterval

    init(request: Request) throws {
        guard request.op == "watch-session", let id = request.expectedInstallationID else { throw Failure("invalid-request") }
        events = WorkspaceWatchEvents()
        let accountRequest = try Request.parse(Data("{\"op\":\"account\",\"installation_id\":\"\(Hex.encode(id))\"}".utf8))
        let provider = NativeProvider()
        var accountGuard = WatchAccountGuard()
        checkAccount = {
            let account = try NativeAccount.read()
            try accountGuard.check(account: account, active: account.hasActiveConsole()) {
                let response = try provider.execute(accountRequest)
                guard try NativeAccount.read() == account else { throw Failure("account-changed") }
                return response["locked"] as? Bool == false
            }
        }
        input = STDIN_FILENO; output = STDOUT_FILENO; seconds = Self.maximumSeconds
    }

    #if WATCH_TEST || SELF_TEST
    init(events: any WatchEvents, checkAccount: @escaping () throws -> Void,
         input: Int32 = STDIN_FILENO, output: Int32 = STDOUT_FILENO, seconds: TimeInterval = 1) {
        self.events = events; self.checkAccount = checkAccount; self.input = input; self.output = output
        self.seconds = min(max(seconds, 0), Self.maximumSeconds)
    }
    #endif

    func run(installationID: Data) throws {
        guard installationID.count == 32, Thread.isMainThread else { throw Failure("invalid-request") }
        let deadline = WatchClock.now() + seconds
        var lastProgress = WatchClock.now()
        let latch = WatchLatch()
        var challenges = WatchChallenges()
        defer { events.cancel() }
        // Subscribe BEFORE any initial account/lock/namespace observation.
        try events.subscribe(latch)
        try events.requireCoverage()
        try checkAccount()
        func freshTime() throws -> TimeInterval {
            let now = WatchClock.now()
            guard !latch.invalidated, now < deadline, now >= lastProgress, now - lastProgress < 1 else {
                throw Failure("watch-unavailable")
            }
            return now
        }
        func drainCoverage() throws {
            _ = try freshTime()
            try pump()
            try events.checkCoverage()
            _ = try freshTime()
        }
        try drainCoverage()
        for fd in [input, output] {
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw Failure("io-failed") }
        }
        guard try emptyInput() else { return }
        let id = Hex.encode(installationID)
        _ = try freshTime()
        try write(["ok": true, "ready": true, "installation_id": id])
        var nextAccountCheck = lastProgress + 1
        do {
            while true {
                try drainCoverage()
                let now = try freshTime()
                if now >= nextAccountCheck {
                    try checkAccount()
                    try drainCoverage()
                    nextAccountCheck = now + 1
                }
                switch try challenges.read(input, now: try freshTime()) {
                case .disconnected: return
                case .idle: break
                case .challenge(let nonce):
                    // This runs on the SAME event loop as native subscriptions,
                    // after a complete drain and again immediately before ACK.
                    // No timer/background thread can vouch for a stalled loop.
                    try drainCoverage()
                    guard try emptyInput() else { return }
                    _ = try freshTime()
                    try write(["ok": true, "installation_id": id, "challenge": nonce])
                }
                // Test the OLD deadline before updating progress, including a
                // stall inside native calls or a stop/resume around a write.
                lastProgress = try freshTime()
                var descriptors = [pollfd(fd: input, events: Int16(POLLIN | POLLHUP), revents: 0),
                                   pollfd(fd: output, events: 0, revents: 0)]
                let status = poll(&descriptors, 2, 20)
                if status < 0 && errno != EINTR { throw Failure("watch-unavailable") }
                if descriptors[1].revents & Int16(POLLHUP | POLLERR | POLLNVAL) != 0 { return }
            }
        } catch { latch.invalidate() }
        // After readiness, failure emits only the irreversible terminal frame.
        try? write(["ok": true, "invalidated": true, "installation_id": id])
    }

    private func pump() throws {
        for _ in 0..<32 {
            let result = CFRunLoopRunInMode(.defaultMode, 0, true)
            if result == .finished || result == .timedOut { return }
            guard result == .handledSource else { throw Failure("watch-unavailable") }
        }
        throw Failure("watch-unavailable")
    }

    private func emptyInput() throws -> Bool {
        for _ in 0..<32 {
            var byte: UInt8 = 0
            let count = Darwin.read(input, &byte, 1)
            if count == 0 { return false }
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { return true }
            // Called before ready and while an ACK is pending: input here is an
            // unsolicited/pipelined request. Normal challenges use WatchChallenges.
            throw Failure("invalid-request")
        }
        throw Failure("invalid-request")
    }

    private func write(_ object: [String: Any]) throws {
        var bytes = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        bytes.append(10)
        guard bytes.count <= 512 else { throw Failure("io-failed") }
        // A sub-PIPE_BUF frame is one nonblocking atomic write. An unread or
        // broken pipe cannot keep this helper alive or expose a partial frame.
        let count = bytes.withUnsafeBytes { Darwin.write(output, $0.baseAddress!, $0.count) }
        guard count == bytes.count else { throw Failure("io-failed") }
    }
}
