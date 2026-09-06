import Foundation
import Darwin

enum WatchClock {
    static let maximumSeconds: TimeInterval = 300
    private static let secondsPerTick: Double = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return Double(info.numer) / Double(info.denom) / 1_000_000_000
    }()
    // Includes sleep, unlike uptime clocks on some supported OS releases.
    static func now() -> TimeInterval { Double(mach_continuous_time()) * secondsPerTick }
    static func generatedAt(absoluteTicks: UInt64) -> TimeInterval? {
        let continuous = mach_continuous_time()
        let absolute = mach_absolute_time()
        guard absoluteTicks <= absolute, absolute - absoluteTicks <= continuous else { return nil }
        return Double(continuous - (absolute - absoluteTicks)) * secondsPerTick
    }
}

enum MonitorFrame {
    static let length = 18 // kind + 16 lowercase hex nanoseconds + LF
    static func encode(_ kind: UInt8, generatedAt: TimeInterval) -> [UInt8] {
        [kind] + Array(String(format: "%016llx", UInt64(generatedAt * 1_000_000_000)).utf8) + [10]
    }
    static func decode(_ bytes: [UInt8]) throws -> (UInt8, TimeInterval) {
        guard bytes.count == length, bytes.last == 10, bytes[0] == 82 || bytes[0] == 72,
              bytes[1..<17].allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              let ticks = UInt64(String(decoding: bytes[1..<17], as: UTF8.self), radix: 16) else {
            throw Failure("watch-unavailable")
        }
        return (bytes[0], Double(ticks) / 1_000_000_000)
    }
}

enum MonitorSocket {
    static let path = "/private/var/run/org.einsatzarchiv.operator.monitor.sock"
    static func address<T>(_ body: (UnsafePointer<sockaddr>, socklen_t) throws -> T) rethrows -> T {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { bytes in
            bytes.copyBytes(from: Array(path.utf8) + [0])
        }
        return try withUnsafePointer(to: &address) {
            try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { try body($0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
    }
    static func nonblocking(_ fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL)
        var one: Int32 = 1
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
              fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw Failure("watch-unavailable")
        }
    }
    static func requireProtectedPath(includeSocket: Bool = true) throws {
        for path in ["/private", "/private/var", "/private/var/run"] + (includeSocket ? [Self.path] : []) {
            var info = stat()
            guard lstat(path, &info) == 0, info.st_uid == 0,
                  info.st_mode & S_IFMT == (path == Self.path ? S_IFSOCK : S_IFDIR),
                  path == Self.path || info.st_mode & 0o022 == 0 else { throw Failure("watch-unavailable") }
        }
    }
}

// Internal daemon protocol is deliberately fixed bytes, never account data:
// R = subscribed and currently eligible, H = coverage heartbeat, I = terminal.
// R/H preserve the ES heartbeat's original continuous-clock time. I is I+LF.
// Old untimestamped peers fail closed; helper and monitor ship together.
final class MonitorConnection {
    private var fd: Int32 = -1
    private var pending: [UInt8] = []
    private var ready = false
    private var lastHeartbeat: TimeInterval = 0
    private var team = ""
    private var nextIdentityCheck: TimeInterval = 0

    init() {}

    #if SELF_TEST || WATCH_STATE_TEST
    // Anonymous socketpair only, compiled out of production. Tests exercise
    // the real bounded parser/drain without requiring a privileged ES daemon.
    init(fixtureSocket: Int32) throws {
        fd = fixtureSocket
        lastHeartbeat = WatchClock.now()
        nextIdentityCheck = lastHeartbeat + 60
        try drain()
    }
    #endif

    func connect() throws {
        team = try CodeIdentity.ownTeam(identifier: CodeIdentity.helper)
        try MonitorSocket.requireProtectedPath()
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure("watch-unavailable") }
        try MonitorSocket.nonblocking(fd)
        let result = MonitorSocket.address { Darwin.connect(fd, $0, $1) }
        if result != 0 {
            guard errno == EINPROGRESS else { throw Failure("watch-unavailable") }
            var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            guard poll(&descriptor, 1, 1000) == 1, descriptor.revents & Int16(POLLOUT) != 0 else { throw Failure("watch-unavailable") }
            var error: Int32 = 0
            var size = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else { throw Failure("watch-unavailable") }
        }
        try authenticate()
        lastHeartbeat = WatchClock.now()
        let deadline = lastHeartbeat + 2
        while !ready && WatchClock.now() < deadline {
            try drain()
            if !ready {
                var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                _ = poll(&descriptor, 1, 20)
            }
        }
        guard ready else { throw Failure("watch-unavailable") }
    }

    func check() throws {
        do {
            guard ready else { throw Failure("watch-unavailable") }
            try requireFresh()
            try drain()
            let now = WatchClock.now()
            if now >= nextIdentityCheck {
                try authenticate(); nextIdentityCheck = now + 1
                // Validating code may block while terminal bytes arrive.
                try drain()
            }
            try requireFresh()
        } catch { close(); throw error }
    }

    private func authenticate() throws { try CodeIdentity.peer(fd, identifier: CodeIdentity.monitor, team: team, root: true) }

    private func drain() throws {
        // Drain to EAGAIN, never merely one chunk. Exceeding either bound is
        // itself coverage loss, so a flood cannot hide a queued I/EOF.
        var budget = 1024
        for _ in 0..<32 {
            var bytes = [UInt8](repeating: 0, count: min(256, budget))
            let count = Darwin.read(fd, &bytes, bytes.count)
            if count < 0 && errno == EINTR { continue }
            if count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) {
                var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                guard poll(&descriptor, 1, 0) >= 0,
                      descriptor.revents & Int16(POLLHUP | POLLERR | POLLNVAL | POLLIN) == 0,
                      pending.isEmpty else { throw Failure("watch-unavailable") }
                return
            }
            guard count > 0 else { throw Failure("watch-unavailable") }
            budget -= count
            for byte in bytes.prefix(count) {
                if pending.isEmpty && byte == 73 { throw Failure("watch-unavailable") }
                pending.append(byte)
                guard pending.count <= MonitorFrame.length else { throw Failure("watch-unavailable") }
                if byte == 10 {
                    let (kind, generatedAt) = try MonitorFrame.decode(pending)
                    guard kind == 82 && !ready || kind == 72 && ready,
                          generatedAt >= 0, generatedAt <= WatchClock.now(),
                          !ready || generatedAt >= lastHeartbeat else { throw Failure("watch-unavailable") }
                    lastHeartbeat = generatedAt
                    try requireFresh()
                    ready = true
                    pending.removeAll(keepingCapacity: true)
                }
            }
            guard budget > 0 else { throw Failure("watch-unavailable") }
        }
        throw Failure("watch-unavailable")
    }
    private func requireFresh() throws {
        let age = WatchClock.now() - lastHeartbeat
        guard age >= 0, age < 1 else { throw Failure("watch-unavailable") }
    }
    func close() { if fd >= 0 { Darwin.close(fd); fd = -1 }; ready = false }
    deinit { close() }
}
