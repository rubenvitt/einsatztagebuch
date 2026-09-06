import Foundation
import EndpointSecurity
import Darwin

// Only scalar event metadata enters this state. No ES usernames, audit tokens,
// file paths or message payloads are retained, logged or transmitted.
final class MonitorState: @unchecked Sendable {
    static let maximumClients = 32
    private let lock = NSLock()
    private var clients: [Int32: TimeInterval] = [:]
    private var expectedSequence: UInt64?
    private var healthy = true
    private var unlockedObserved = false
    private var lastHeartbeat: TimeInterval?
    private var lastBroadcast: TimeInterval?

    func event(sequence: UInt64, version: UInt32, unlock: Bool?, heartbeat: Bool = false,
               now: TimeInterval = WatchClock.now(), generatedAt: TimeInterval? = nil) {
        lock.lock(); defer { lock.unlock() }
        guard healthy else { return }
        let generated = generatedAt ?? now
        guard now.isFinite, generated.isFinite, generated >= 0, now >= generated, now - generated < 1,
              preserveFreshness(now: now) else { healthy = false; invalidateAll(); return }
        guard version >= 4, expectedSequence == nil || sequence == expectedSequence, sequence < UInt64.max else {
            healthy = false; invalidateAll(); return
        }
        expectedSequence = sequence + 1
        if heartbeat {
            guard lastHeartbeat == nil || generated >= lastHeartbeat! else { healthy = false; invalidateAll(); return }
            lastHeartbeat = generated
        }
        guard let unlock else { return }
        // Lock/logout/login/unlock all terminate existing sessions. A fresh
        // observed login/unlock permits a NEW connection only. Startup is
        // unknown until such an ES event, never assumed initially unlocked.
        invalidateAll()
        unlockedObserved = unlock
    }

    func loseCoverage() { lock.lock(); defer { lock.unlock() }; healthy = false; invalidateAll() }

    func add(_ fd: Int32, now: TimeInterval) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard healthy, preserveFreshness(now: now), unlockedObserved, let lastHeartbeat,
              clients.count < Self.maximumClients else { return false }
        guard send(fd, 82, generatedAt: lastHeartbeat) else { return false }
        clients[fd] = now + WatchClock.maximumSeconds
        return true
    }

    func tick(now: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        guard healthy, preserveFreshness(now: now) else { return }
        let broadcast = lastBroadcast == nil || now - lastBroadcast! >= 0.1
        if broadcast { lastBroadcast = now }
        for (fd, deadline) in Array(clients) {
            var byte: UInt8 = 0
            let count = Darwin.read(fd, &byte, 1)
            if now >= deadline || count >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                || (broadcast && !send(fd, 72, generatedAt: lastHeartbeat ?? 0)) {
                _ = send(fd, 73); Darwin.close(fd); clients.removeValue(forKey: fd)
            }
        }
    }

    private func invalidateAll() {
        for fd in clients.keys { _ = send(fd, 73); Darwin.close(fd) }
        clients.removeAll()
    }
    private func preserveFreshness(now: TimeInterval) -> Bool {
        if let lastHeartbeat, !now.isFinite || now < lastHeartbeat || now - lastHeartbeat >= 1 {
            healthy = false; invalidateAll(); return false
        }
        return true
    }
    private func send(_ fd: Int32, _ byte: UInt8, generatedAt: TimeInterval = 0) -> Bool {
        let bytes = byte == 73 ? [byte, 10] : MonitorFrame.encode(byte, generatedAt: generatedAt)
        return bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, $0.count) } == bytes.count
    }
}

enum MonitorDaemon {
    // NOTIFY only. No AUTH event, authorization response or operation blocking.
    static let events = [ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK, ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT,
                         ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK,
                         ES_EVENT_TYPE_NOTIFY_EXIT]

    static func run() throws {
        guard #available(macOS 13.0, *), getuid() == 0, geteuid() == 0 else { throw Failure("watch-unavailable") }
        let team = try CodeIdentity.ownTeam(identifier: CodeIdentity.monitor)
        try MonitorSocket.requireProtectedPath(includeSocket: false)
        let lockFD = open(MonitorSocket.path + ".lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard lockFD >= 0 else { throw Failure("watch-unavailable") }
        defer { Darwin.close(lockFD) }
        var lockInfo = stat()
        guard fstat(lockFD, &lockInfo) == 0, lockInfo.st_uid == 0, lockInfo.st_nlink == 1,
              lockInfo.st_mode & S_IFMT == S_IFREG, lockInfo.st_mode & 0o777 == 0o600,
              flock(lockFD, LOCK_EX | LOCK_NB) == 0 else { throw Failure("watch-unavailable") }
        let state = MonitorState()
        var client: OpaquePointer?
        guard es_new_client(&client, { _, message in
            let value = message.pointee
            guard let generated = WatchClock.generatedAt(absoluteTicks: value.mach_time) else { state.loseCoverage(); return }
            let isExit = value.event_type == ES_EVENT_TYPE_NOTIFY_EXIT
            state.event(sequence: value.version >= 4 ? value.global_seq_num : UInt64.max, version: value.version,
                        unlock: isExit ? nil : (value.event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN || value.event_type == ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK),
                        heartbeat: isExit && value.process.pointee.ppid == getpid(), generatedAt: generated)
        }) == ES_NEW_CLIENT_RESULT_SUCCESS, let client else { throw Failure("watch-unavailable") }
        defer { state.loseCoverage(); es_delete_client(client) }
        guard es_subscribe(client, events, UInt32(events.count)) == ES_RETURN_SUCCESS else { throw Failure("watch-unavailable") }
        // Clear default path mutes for our five NOTIFY events only; no AUTH
        // events are subscribed. A muted loginwindow must not create a blind spot.
        guard es_unmute_all_paths(client) == ES_RETURN_SUCCESS,
              es_unmute_all_target_paths(client) == ES_RETURN_SUCCESS else { throw Failure("watch-unavailable") }
        try requireSubscriptions(client)

        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw Failure("watch-unavailable") }
        defer { Darwin.close(listener) }
        try MonitorSocket.nonblocking(listener)
        // Serialize daemon instances before removing a stale root-owned socket.
        var previous = stat()
        if lstat(MonitorSocket.path, &previous) == 0 {
            guard previous.st_uid == 0, previous.st_mode & S_IFMT == S_IFSOCK, previous.st_nlink == 1,
                  unlink(MonitorSocket.path) == 0 else { throw Failure("watch-unavailable") }
        } else if errno != ENOENT { throw Failure("watch-unavailable") }
        let oldMask = umask(0o111)
        let bound = MonitorSocket.address { bind(listener, $0, $1) }
        umask(oldMask)
        guard bound == 0 else { throw Failure("watch-unavailable") }
        defer { unlink(MonitorSocket.path) }
        try MonitorSocket.requireProtectedPath()
        guard listen(listener, 8) == 0 else { throw Failure("watch-unavailable") }
        var last = WatchClock.now()
        var nextHeartbeat = last
        var heartbeatChild: Process?
        defer {
            // The only child is /usr/bin/true. Never signal an unrelated process.
            if let child = heartbeatChild, child.isRunning { child.terminate() }
        }
        while true {
            var descriptor = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
            let result = poll(&descriptor, 1, 100)
            let now = WatchClock.now()
            guard now - last < 1, result >= 0 || errno == EINTR else { throw Failure("watch-unavailable") }
            last = now
            if now >= nextHeartbeat {
                guard heartbeatChild?.isRunning != true else { throw Failure("watch-unavailable") }
                let child = Process()
                child.executableURL = URL(fileURLWithPath: "/usr/bin/true")
                child.arguments = []; child.environment = [:]
                child.standardInput = FileHandle.nullDevice
                child.standardOutput = FileHandle.nullDevice
                child.standardError = FileHandle.nullDevice
                try child.run()
                heartbeatChild = child
                nextHeartbeat = now + 0.25
            }
            try requireSubscriptions(client)
            state.tick(now: now)
            if descriptor.revents & Int16(POLLIN) != 0 {
                // One connection per tick bounds authentication work and queue.
                let fd = accept(listener, nil, nil)
                if fd >= 0 {
                    do {
                        try MonitorSocket.nonblocking(fd)
                        try CodeIdentity.peer(fd, identifier: CodeIdentity.helper, team: team, root: false)
                        if !state.add(fd, now: WatchClock.now()) { Darwin.close(fd) }
                    } catch { Darwin.close(fd) }
                }
            }
        }
    }

    private static func requireSubscriptions(_ client: OpaquePointer) throws {
        var count = 0
        let storage = UnsafeMutablePointer<UnsafeMutablePointer<es_event_type_t>>.allocate(capacity: 1)
        defer { storage.deallocate() }
        guard es_subscriptions(client, &count, storage) == ES_RETURN_SUCCESS else { throw Failure("watch-unavailable") }
        let subscribed = storage.pointee
        defer { free(subscribed) }
        guard count == events.count,
              Set(UnsafeBufferPointer(start: subscribed, count: count)) == Set(events) else { throw Failure("watch-unavailable") }
    }
}
