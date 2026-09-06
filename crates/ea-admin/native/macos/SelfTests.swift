#if SELF_TEST
import Foundation
import CryptoKit
import Darwin
import LocalAuthentication

enum SelfTests {
    static func run() throws {
        var count = 0
        func check(_ condition: @autoclosure () throws -> Bool) throws {
            guard try condition() else { throw Failure("self-test-check-\(count + 1)") }
            count += 1
        }
        func rejects(_ expected: String, _ body: () throws -> Void) throws {
            do { try body(); throw Failure("self-test-unexpected-success") }
            catch let error as Failure {
                guard error.code == expected else { throw Failure("self-test-check-\(count + 1)-expected-" + expected + "-got-" + error.code) }
                try check(true)
            }
        }
        func parse(_ text: String) throws -> Request { try Request.parse(Data(text.utf8)) }
        try check(try parse("{\"op\":\"account\"}").op == "account")
        for text in ["{}", "[]", "null", "{\"op\":\"account\",\"op\":\"initialize\"}",
                     "{\"op\":\"account\",\"presence\":1}", "{\"op\":\"account\",\"uid\":501}",
                     "{\"op\":\"account\",\"presence\":true}", "{\"op\":\"account\"}{}",
                     "{\"op\":\"contains\",\"slot\":\"../root-signing\"}",
                     "{\"op\":\"contains\",\"slot\":\"\"}",
                     "{\"op\":\"contains\",\"slot\":\"ROOT\"}",
                     "{\"op\":\"contains\",\"slot\":\"a\",\"sl\\u006ft\":\"b\"}"] {
            try rejects("invalid-request") { _ = try parse(text) }
        }
        try rejects("request-too-large") { _ = try Request.parse(Data(repeating: 32, count: 65_537)) }
        for slot in ["operator-instance", "admin-signing", "root-signing"] {
            try rejects("presence-required") {
                _ = try parse("{\"op\":\"sign\",\"slot\":\"\(slot)\",\"data\":\"\"}")
            }
        }
        try check(try parse("{\"op\":\"sign\",\"slot\":\"writer-signing\",\"data\":\"\",\"presence\":false}").presence == false)
        for slot in ["root-signing", "operator-instance", "writer-signing", "admin-signing", "database-key-evil", "draft"] {
            try rejects("invalid-request") { _ = try parse("{\"op\":\"unwrap-secret\",\"slot\":\"\(slot)\"}") }
        }
        try rejects("invalid-request") { _ = try parse("{\"op\":\"generate\",\"slot\":\"root-signing\",\"kind\":\"ed25519\",\"replace\":true,\"presence\":true}") }
        try check(try parse("{\"op\":\"generate\",\"slot\":\"operator-instance\",\"kind\":\"ed25519\",\"replace\":true,\"presence\":true}").replace)
        try rejects("invalid-request") { _ = try parse("{\"op\":\"wrap-secret\",\"slot\":\"database-key\",\"data\":\"aa\"}") }
        let key = Curve25519.Signing.PrivateKey()
        let message = Data("ea-native-self-test-signature".utf8)
        let signature = try key.signature(for: message)
        try check(key.publicKey.isValidSignature(signature, for: message))
        try check(!key.publicKey.isValidSignature(signature, for: Data("changed".utf8)))
        try check(key.publicKey.rawRepresentation.count == 32 && signature.count == 64)
        try check(try Hex.decode(Hex.encode(message)) == message)
        try rejects("invalid-request") { _ = try Hex.decode("AA") }
        try rejects("invalid-request") { _ = try Hex.decode("a") }
        let uid = getuid()
        let account = try FixtureAccount.read()
        try check(account.uid == uid && getuid() == uid)
        try check(account.guidValues == [FixtureAccount.guid] && account.uniqueIDValues == [String(uid)])
        try check(account.bindingDigest.count == 32)
        try rejects("account-invalid") { _ = try NativeAccount.validate(guidValues: ["00000000-0000-0000-0000-000000000000"], uniqueIDValues: [String(uid)], uid: uid) }
        try rejects("account-invalid") { _ = try NativeAccount.validate(guidValues: account.guidValues, uniqueIDValues: [String(uid), String(uid)], uid: uid) }
        try rejects("account-invalid") { _ = try NativeAccount.validate(guidValues: account.guidValues, uniqueIDValues: [String(uid + 1)], uid: uid) }
        try testProvider(check: check, rejects: rejects, account: account)
        let providerCount = count
        try WatchTests.run(check: check, rejects: rejects)
        // Only counts leave the self-test; no live directory/account query runs.
        print("{\"ok\":true,\"self_tests\":\(count),\"provider_self_tests\":\(providerCount),\"watch_state_tests\":\(count - providerCount)}")
    }

    static func testProvider(check: ((() throws -> Bool)) throws -> Void,
                             rejects: (String, () throws -> Void) throws -> Void,
                             account: NativeAccount) throws {
        let temporary = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("ea-native-isolated-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: temporary) }
        let directory = temporary.appendingPathComponent("marker", isDirectory: true)
        let markerURL = directory.appendingPathComponent("installation-v1")
        let memory = MemoryKeys()
        let backupPolicy = FixtureBackupPolicy(directory: directory)
        var consoleActive = true
        var presenceCalls = 0
        var currentAccount = account
        let provider = NativeProvider(keys: memory, accountReader: { currentAccount }, consoleCheck: { _ in consoleActive },
                                      authenticate: { _ in presenceCalls += 1; return LAContext() }, markerDirectory: { _ in directory },
                                      backupCheck: backupPolicy.check)
        func call(_ text: String) throws -> [String: Any] { try provider.execute(Request.parse(Data(text.utf8))) }
        try rejects("installation-missing") { _ = try call("{\"op\":\"account\"}") }
        try check { memory.reads == 0 && memory.writes == 0 }
        let initialized = try call("{\"op\":\"initialize\"}")
        try check { backupPolicy.checked.contains(directory.path) }
        try check { backupPolicy.checked.contains(markerURL.path) }
        let oldID = initialized["installation_id"] as? String
        try check { oldID?.count == 64 && initialized["locked"] as? Bool == false }
        let marker = try Installation.decode(Data(contentsOf: markerURL), account: account)
        let beforeWrongID = memory.reads
        try rejects("installation-changed") { _ = try call("{\"op\":\"account\",\"installation_id\":\"\(String(repeating: "00", count: 32))\"}") }
        try check { memory.reads == beforeWrongID }
        try check { try call("{\"op\":\"account\",\"installation_id\":\"\(marker.idHex)\"}")["installation_id"] as? String == marker.idHex }
        try check { marker.id != marker.wrappingKey && marker.accountInstance != marker.wrappingKey }
        try check { !marker.namespaceValue.containsSubsequence(marker.wrappingKey) }
        try check { !(try JSONSerialization.data(withJSONObject: initialized)).containsSubsequence(Data(Hex.encode(marker.wrappingKey).utf8)) }
        try check { memory.namespaces[marker.service] == marker.namespaceValue }
        let returned = try call("{\"op\":\"initialize\"}")
        try check { returned["installation_id"] as? String == oldID && memory.writes == 1 }
        let generated = try call("{\"op\":\"generate\",\"slot\":\"operator-instance\",\"kind\":\"ed25519\",\"presence\":true}")
        try check { generated["installation_id"] as? String == oldID && Set(generated.keys) == ["ok", "installation_id", "public_key"] }
        let publicHex = generated["public_key"] as! String
        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: Hex.decode(publicHex))
        let signed = try call("{\"op\":\"sign\",\"slot\":\"operator-instance\",\"presence\":true,\"data\":\"616263\"}")
        let sig = try Hex.decode(signed["signature"] as! String)
        try check { publicKey.isValidSignature(sig, for: Data("abc".utf8)) }
        try check { Set(signed.keys) == ["ok", "installation_id", "signature"] }
        try rejects("key-exists") { _ = try call("{\"op\":\"generate\",\"slot\":\"operator-instance\",\"kind\":\"ed25519\"}") }
        let callsBeforeMetadata = presenceCalls
        let publicResponse = try call("{\"op\":\"public-key\",\"slot\":\"operator-instance\"}")
        try check { publicResponse["public_key"] as? String == publicHex && presenceCalls == callsBeforeMetadata }
        let contains = try call("{\"op\":\"contains\",\"slot\":\"operator-instance\"}")
        try check { contains["contains"] as? Bool == true && contains["installation_id"] as? String == oldID }
        let replacement = try call("{\"op\":\"generate\",\"slot\":\"operator-instance\",\"kind\":\"ed25519\",\"replace\":true,\"presence\":true}")
        try check { replacement["public_key"] as? String != publicHex }
        _ = try call("{\"op\":\"generate\",\"slot\":\"writer-signing\",\"kind\":\"ed25519\"}")
        let beforeWriterSign = presenceCalls
        _ = try call("{\"op\":\"sign\",\"slot\":\"writer-signing\",\"presence\":false,\"data\":\"\"}")
        try check { presenceCalls == beforeWriterSign }
        let secret = String(repeating: "3a", count: 32)
        let wrapped = try call("{\"op\":\"wrap-secret\",\"slot\":\"database-key\",\"data\":\"\(secret)\"}")
        try check { Set(wrapped.keys) == ["ok", "installation_id"] }
        let unwrapped = try call("{\"op\":\"unwrap-secret\",\"slot\":\"database-key\"}")
        try check { unwrapped["secret"] as? String == secret && unwrapped["installation_id"] as? String == oldID }
        try rejects("key-exists") { _ = try call("{\"op\":\"wrap-secret\",\"slot\":\"database-key\",\"data\":\"\(secret)\"}") }
        let dbMetadata = StoredKey(kind: "secret32", publicKey: nil)
        let dbCiphertext = memory.values[marker.service]!["database-key"]!.1
        let secretBytes = try Hex.decode(secret)
        try check { dbCiphertext.count == 60 && dbCiphertext != secretBytes }
        let publicIDOpensCiphertext = (try? ChaChaPoly.open(ChaChaPoly.SealedBox(combined: dbCiphertext),
            using: SymmetricKey(data: marker.id), authenticating: marker.associatedData(slot: "database-key", metadata: dbMetadata))) != nil
        try check { !publicIDOpensCiphertext }
        try rejects("key-invalid") { _ = try marker.open(dbCiphertext, slot: "draft-key", metadata: dbMetadata) }
        var damaged = dbCiphertext
        damaged[20] ^= 1
        try rejects("key-invalid") { _ = try marker.open(damaged, slot: "database-key", metadata: dbMetadata) }
        let otherInstallation = try Installation.fresh(account: account)
        try rejects("key-invalid") { _ = try otherInstallation.open(dbCiphertext, slot: "database-key", metadata: dbMetadata) }
        let deniedPipe = NativeProvider(keys: memory, accountReader: { account }, consoleCheck: { _ in true },
                                        authenticate: { _ in LAContext() }, markerDirectory: { _ in directory },
                                        pipeCheck: { throw Failure("protected-pipe-required") }, backupCheck: backupPolicy.check)
        let readsBeforePipeDenial = memory.secretReads
        try rejects("protected-pipe-required") {
            _ = try deniedPipe.execute(Request.parse(Data("{\"op\":\"unwrap-secret\",\"slot\":\"database-key\"}".utf8)))
        }
        try check { memory.secretReads == readsBeforePipeDenial }
        consoleActive = false
        try check { try call("{\"op\":\"account\"}")["locked"] as? Bool == true }
        try rejects("locked") { _ = try call("{\"op\":\"sign\",\"slot\":\"writer-signing\",\"data\":\"\"}") }
        consoleActive = true
        memory.locked = true
        try check { try call("{\"op\":\"account\"}")["locked"] as? Bool == true }
        try rejects("locked") { _ = try call("{\"op\":\"public-key\",\"slot\":\"operator-instance\"}") }
        memory.locked = false
        // A lock during secret retrieval must suppress the successful result.
        memory.afterSecretRead = { memory.locked = true }
        try rejects("locked") { _ = try call("{\"op\":\"sign\",\"slot\":\"writer-signing\",\"data\":\"\"}") }
        memory.afterSecretRead = nil
        memory.locked = false
        let otherAccount = try NativeAccount.validate(guidValues: ["12345678-1234-4234-8234-123456789abc"], uniqueIDValues: [String(account.uid)], uid: account.uid)
        memory.afterSecretRead = { currentAccount = otherAccount }
        try rejects("account-changed") { _ = try call("{\"op\":\"sign\",\"slot\":\"writer-signing\",\"data\":\"\"}") }
        memory.afterSecretRead = nil
        currentAccount = account
        // The positive policy decision is an explicit fixture; the refusal
        // path below must still stop before any Keychain access. Effective OS
        // backup exclusion belongs to the separate manual read-only suite.
        let exclusionDenied = NativeProvider(keys: memory, accountReader: { account }, consoleCheck: { _ in true },
                                             authenticate: { _ in LAContext() }, markerDirectory: { _ in directory },
                                             backupCheck: { _ in throw Failure("backup-exclusion-failed") })
        let beforeExcludedFailure = memory.reads
        try rejects("backup-exclusion-failed") { _ = try exclusionDenied.execute(Request.parse(Data("{\"op\":\"account\"}".utf8))) }
        try check { memory.reads == beforeExcludedFailure }
        // Removing the marker cannot trigger a search of any surviving namespace.
        try FileManager.default.removeItem(at: markerURL)
        let beforeLoss = memory.reads
        try rejects("installation-missing") { _ = try call("{\"op\":\"account\"}") }
        try check { memory.reads == beforeLoss }
        let reinitialized = try call("{\"op\":\"initialize\"}")
        try check { reinitialized["installation_id"] as? String != oldID && memory.namespaces.count == 2 }
        try check { try call("{\"op\":\"contains\",\"slot\":\"operator-instance\"}")["contains"] as? Bool == false }
        let newMarker = try Installation.decode(Data(contentsOf: markerURL), account: account)
        try rejects("key-invalid") { _ = try newMarker.open(dbCiphertext, slot: "database-key", metadata: dbMetadata) }
        let reset = try call("{\"op\":\"reset\",\"presence\":true}")
        try check { reset["reset"] as? Bool == true && reset["installation_id"] as? String == newMarker.idHex }
        try check { !FileManager.default.fileExists(atPath: markerURL.path) }
        try rejects("installation-missing") { _ = try call("{\"op\":\"account\"}") }
        // A symlink must not redirect any marker read into another file.
        let target = temporary.appendingPathComponent("not-a-marker")
        try Data("not secret".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: markerURL, withDestinationURL: target)
        try rejects("installation-invalid") { _ = try call("{\"op\":\"account\"}") }
        try FileManager.default.removeItem(at: markerURL)
        _ = try call("{\"op\":\"initialize\"}")
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: markerURL.path)
        try rejects("installation-invalid") { _ = try call("{\"op\":\"account\"}") }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: markerURL.path)
        _ = try call("{\"op\":\"generate\",\"slot\":\"draft-key\",\"kind\":\"secret32\"}")
        let deleted = try call("{\"op\":\"delete\",\"slot\":\"draft-key\"}")
        try check { Set(deleted.keys) == ["ok", "installation_id"] }
        try check { try call("{\"op\":\"contains\",\"slot\":\"draft-key\"}")["contains"] as? Bool == false }
        try check { try call("{\"op\":\"public-key\",\"slot\":\"draft-key\"}")["public_key"] is NSNull }
    }
}

// Typed account injection exists only in SELF_TEST. The GUID is synthetic;
// getuid() supplies ownership for temporary files, never account discovery.
private enum FixtureAccount {
    static let guid = "11111111-2222-4333-8444-555555555555"
    static func read() throws -> NativeAccount {
        let uid = getuid()
        return try NativeAccount.validate(guidValues: [guid], uniqueIDValues: [String(uid)], uid: uid)
    }
}

private final class FixtureBackupPolicy {
    let directory: URL
    private(set) var checked: Set<String> = []
    init(directory: URL) { self.directory = directory }
    func check(_ url: URL) throws {
        guard url == directory || url.deletingLastPathComponent() == directory else { throw Failure("self-test-backup-path") }
        checked.insert(url.path)
    }
}

private extension Data {
    func containsSubsequence(_ value: Data) -> Bool { range(of: value) != nil }
}

// Entirely in-memory, linked only into the SELF_TEST executable. No production
// environment flag or request can select this store or bypass OS presence.
private final class MemoryKeys: NativeKeyStore {
    var namespaces: [String: Data] = [:]
    var values: [String: [String: (StoredKey, Data)]] = [:]
    var reads = 0
    var writes = 0
    var secretReads = 0
    var locked = false
    var afterSecretRead: (() -> Void)?
    func namespace(_ installation: Installation, context: LAContext) throws -> Data? {
        reads += 1
        if locked { throw Failure("locked") }
        return namespaces[installation.service]
    }
    func createNamespace(_ installation: Installation, context: LAContext) throws {
        guard namespaces[installation.service] == nil else { throw Failure("key-exists") }
        namespaces[installation.service] = installation.namespaceValue
        writes += 1
    }
    func metadata(_ installation: Installation, slot: String, context: LAContext) throws -> StoredKey? {
        reads += 1
        return values[installation.service]?[slot]?.0
    }
    func read(_ installation: Installation, slot: String, context: LAContext) throws -> Data {
        reads += 1; secretReads += 1
        guard let value = values[installation.service]?[slot]?.1 else { throw Failure("key-missing") }
        afterSecretRead?()
        return value
    }
    func put(_ installation: Installation, slot: String, metadata: StoredKey, data: Data, replace: Bool, context: LAContext) throws {
        guard values[installation.service]?[slot] == nil || replace else { throw Failure("key-exists") }
        values[installation.service, default: [:]][slot] = (metadata, data)
        writes += 1
    }
    func delete(_ installation: Installation, slot: String, context: LAContext) throws {
        values[installation.service]?[slot] = nil
        writes += 1
    }
}
#endif
