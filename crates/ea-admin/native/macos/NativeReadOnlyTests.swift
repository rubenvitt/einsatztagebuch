#if NATIVE_READ_ONLY_TEST
import Foundation
import Darwin

// Explicit manual host probes, separate from deterministic provider tests.
// No Keychain, LA evaluation, production marker path, or ES client is used.
enum NativeReadOnlyTests {
    static func run() throws {
        var count = 0
        func check(_ condition: Bool) throws {
            guard condition else { throw Failure("native-read-only-check-\(count + 1)") }
            count += 1
        }
        let account = try NativeAccount.read()
        try check(account.uid == getuid() && account.uid == geteuid())
        try check(account.guidValues.count == 1 && account.uniqueIDValues == [String(account.uid)])
        try check(account.bindingDigest.count == 32)
        let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("ea-native-host-probe-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        try MarkerStore.exclude(directory)
        try MarkerStore.requireExcluded(directory)
        try check(true)
        let file = directory.appendingPathComponent("disposable-fixture")
        try Data("public test fixture".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        try MarkerStore.exclude(file)
        try MarkerStore.requireExcluded(file)
        try check(true)
        // Never emit the live UID/GUID, home directory, or account digest.
        print("{\"ok\":true,\"native_read_only_tests\":\(count)}")
    }
}
#endif
