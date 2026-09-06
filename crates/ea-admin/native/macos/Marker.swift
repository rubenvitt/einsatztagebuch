import Foundation
import Security
import CryptoKit
import Darwin

struct Installation: Equatable {
    static let header = Data("EAMAC001".utf8)
    let id: Data
    let accountInstance: Data
    let accountDigest: Data
    let wrappingKey: Data
    var bytes: Data { Self.header + id + accountInstance + accountDigest + wrappingKey }
    // This value may enter Keychain backups; it must never contain wrappingKey.
    var namespaceValue: Data { Data("EAMACNS1".utf8) + id + accountInstance + accountDigest + Data(SHA256.hash(data: wrappingKey)) }
    var idHex: String { Hex.encode(id) }
    var service: String { "org.einsatzarchiv.native.macos.v1." + Hex.encode(accountInstance) + "." + idHex }

    static func fresh(account: NativeAccount) throws -> Installation {
        Installation(id: try random32(), accountInstance: try random32(), accountDigest: account.bindingDigest, wrappingKey: try random32())
    }
    static func random32() throws -> Data {
        var bytes = Data(count: 32)
        let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { throw Failure("entropy-unavailable") }
        return bytes
    }
    static func decode(_ bytes: Data, account: NativeAccount) throws -> Installation {
        guard bytes.count == 136, bytes.prefix(8) == header else { throw Failure("installation-invalid") }
        let value = Installation(id: Data(bytes[8..<40]), accountInstance: Data(bytes[40..<72]), accountDigest: Data(bytes[72..<104]), wrappingKey: Data(bytes[104..<136]))
        guard value.id.contains(where: { $0 != 0 }), value.accountInstance.contains(where: { $0 != 0 }),
              value.wrappingKey.contains(where: { $0 != 0 }), value.accountDigest == account.bindingDigest else { throw Failure("installation-invalid") }
        return value
    }

    func associatedData(slot: String, metadata: StoredKey) -> Data {
        // Length-delimit the only variable field; metadata also authenticates the
        // public key and kind so ciphertext cannot be relabeled across slots.
        Data("EINSATZARCHIV-NATIVE-MACOS-WRAP-v1\0".utf8) + namespaceValue
            + Data([UInt8(slot.utf8.count)]) + Data(slot.utf8) + metadata.metadata
    }

    func seal(_ secret: Data, slot: String, metadata: StoredKey) throws -> Data {
        guard secret.count == 32 else { throw Failure("key-invalid") }
        do {
            return try ChaChaPoly.seal(secret, using: SymmetricKey(data: wrappingKey),
                                       authenticating: associatedData(slot: slot, metadata: metadata)).combined
        } catch { throw Failure("crypto-failed") }
    }

    func open(_ ciphertext: Data, slot: String, metadata: StoredKey) throws -> Data {
        guard ciphertext.count == 60 else { throw Failure("key-invalid") }
        do {
            return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: ciphertext), using: SymmetricKey(data: wrappingKey),
                                       authenticating: associatedData(slot: slot, metadata: metadata))
        } catch { throw Failure("key-invalid") }
    }
}

// Only the main executable chooses the location, from getpwuid_r(getuid()).
// No protocol field, profile, environment variable or Keychain search chooses it.
final class MarkerStore {
    let directory: URL
    let account: NativeAccount
    private let backupCheck: (URL) throws -> Void
    private var directoryFD: Int32 = -1
    private let filename = "installation-v1"

    init(directory: URL, account: NativeAccount, backupCheck: @escaping (URL) throws -> Void = MarkerStore.requireExcluded) {
        self.directory = directory; self.account = account; self.backupCheck = backupCheck
    }

    func withLock<T>(create: Bool, _ body: () throws -> T) throws -> T {
        directoryFD = try openDirectory(create: create)
        defer { close(directoryFD); directoryFD = -1 }
        let lockFD = openat(directoryFD, "lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard lockFD >= 0 else { throw Failure("installation-invalid") }
        defer { close(lockFD) }
        try validateFile(lockFD)
        guard flock(lockFD, LOCK_EX | LOCK_NB) == 0 else { throw Failure("busy") }
        defer { _ = flock(lockFD, LOCK_UN) }
        try checkDirectory()
        return try body()
    }

    func load() throws -> Installation? {
        try checkDirectory()
        let fd = openat(directoryFD, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0 && errno == ENOENT { return nil }
        guard fd >= 0 else { throw Failure("installation-invalid") }
        defer { close(fd) }
        try validateFile(fd, expectedSize: 136)
        try backupCheck(directory.appendingPathComponent(filename))
        var bytes = [UInt8](repeating: 0, count: 137)
        var length = 0
        while length < bytes.count {
            let count = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: length), $0.count - length) }
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw Failure("installation-invalid") }
            if count == 0 { break }
            length += count
        }
        var opened = stat()
        var named = stat()
        guard fstat(fd, &opened) == 0, fstatat(directoryFD, filename, &named, AT_SYMLINK_NOFOLLOW) == 0,
              opened.st_ino == named.st_ino, opened.st_dev == named.st_dev, named.st_nlink == 1 else { throw Failure("installation-invalid") }
        return try Installation.decode(Data(bytes.prefix(length)), account: account)
    }

    func recheck(_ installation: Installation) throws {
        guard try load() == installation, getuid() == account.uid, geteuid() == account.uid else { throw Failure("installation-changed") }
    }

    func publish(_ installation: Installation) throws {
        try checkDirectory()
        guard try load() == nil else { throw Failure("installation-exists") }
        let tempName = "pending-" + Hex.encode(try Installation.random32())
        let fd = openat(directoryFD, tempName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw Failure("installation-invalid") }
        defer { close(fd); _ = unlinkat(directoryFD, tempName, 0) }
        let tempURL = directory.appendingPathComponent(tempName)
        // Set exclusion before writing any namespace identifier into the file.
        try Self.exclude(tempURL)
        try backupCheck(tempURL)
        let bytes = installation.bytes
        try bytes.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw Failure("installation-invalid") }
                offset += count
            }
        }
        guard fsync(fd) == 0 else { throw Failure("installation-invalid") }
        // EXCL never overwrites a marker installed by another process.
        guard renameatx_np(directoryFD, tempName, directoryFD, filename, UInt32(RENAME_EXCL)) == 0 else { throw Failure("installation-exists") }
        guard fsync(directoryFD) == 0 else { throw Failure("installation-invalid") }
        try recheck(installation)
    }

    func reset(_ installation: Installation) throws {
        try recheck(installation)
        guard unlinkat(directoryFD, filename, 0) == 0, fsync(directoryFD) == 0 else { throw Failure("installation-invalid") }
        guard try load() == nil else { throw Failure("installation-changed") }
    }

    private func openDirectory(create: Bool) throws -> Int32 {
        let components = directory.path.split(separator: "/").map(String.init)
        guard directory.path.hasPrefix("/"), !components.isEmpty,
              !components.contains("."), !components.contains("..") else { throw Failure("installation-invalid") }
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw Failure("installation-invalid") }
        do {
            for (index, component) in components.enumerated() {
                var created = false
                var next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                if next < 0 && errno == ENOENT && create {
                    if mkdirat(fd, component, mode_t(0o700)) == 0 { created = true }
                    else if errno != EEXIST { throw Failure("installation-invalid") }
                    next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                }
                guard next >= 0 else {
                    throw Failure(errno == ENOENT ? "installation-missing" : "installation-invalid")
                }
                close(fd)
                fd = next
                if index == components.count - 1 && created { try Self.exclude(directory) }
            }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_uid == account.uid,
                  info.st_mode & 0o777 == 0o700 else { throw Failure("installation-invalid") }
            try backupCheck(directory)
            return fd
        } catch { close(fd); throw error }
    }

    private func checkDirectory() throws {
        var opened = stat()
        var named = stat()
        guard directoryFD >= 0, fstat(directoryFD, &opened) == 0, lstat(directory.path, &named) == 0,
              opened.st_ino == named.st_ino, opened.st_dev == named.st_dev,
              named.st_uid == account.uid, named.st_mode & S_IFMT == S_IFDIR,
              named.st_mode & 0o777 == 0o700 else { throw Failure("installation-invalid") }
        try backupCheck(directory)
    }

    private func validateFile(_ fd: Int32, expectedSize: Int64? = nil) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == account.uid, info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o777 == 0o600, info.st_nlink == 1,
              expectedSize == nil || info.st_size == expectedSize else { throw Failure("installation-invalid") }
    }

    static func exclude(_ url: URL) throws {
        do { try (url as NSURL).setResourceValue(true, forKey: .isExcludedFromBackupKey) }
        catch { throw Failure("backup-exclusion-failed") }
    }

    static func requireExcluded(_ url: URL) throws {
        do {
            let fresh = NSURL(fileURLWithPath: url.path)
            fresh.removeAllCachedResourceValues()
            var value: AnyObject?
            try fresh.getResourceValue(&value, forKey: .isExcludedFromBackupKey)
            guard (value as? NSNumber)?.boolValue == true else { throw Failure("backup-exclusion-failed") }
        } catch { throw Failure("backup-exclusion-failed") }
    }
}
