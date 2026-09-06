import Foundation
import CryptoKit
import LocalAuthentication

final class NativeProvider {
    private let keys: any NativeKeyStore
    private let accountReader: () throws -> NativeAccount
    private let consoleCheck: (NativeAccount) -> Bool
    private let authenticate: (Bool) throws -> LAContext
    private let markerDirectory: (NativeAccount) throws -> URL
    private let pipeCheck: () throws -> Void
    private let backupCheck: (URL) throws -> Void

    init() {
        keys = KeychainStore()
        accountReader = NativeAccount.read
        consoleCheck = { $0.hasActiveConsole() }
        authenticate = { try NativePresence.context(requirePresence: $0) }
        markerDirectory = { try $0.fixedMarkerDirectory() }
        pipeCheck = Transport.requirePrivatePipes
        backupCheck = MarkerStore.requireExcluded
    }

    #if SELF_TEST
    init(keys: any NativeKeyStore, accountReader: @escaping () throws -> NativeAccount,
         consoleCheck: @escaping (NativeAccount) -> Bool, authenticate: @escaping (Bool) throws -> LAContext,
         markerDirectory: @escaping (NativeAccount) throws -> URL, pipeCheck: @escaping () throws -> Void = {},
         backupCheck: @escaping (URL) throws -> Void = MarkerStore.requireExcluded) {
        self.keys = keys; self.accountReader = accountReader; self.consoleCheck = consoleCheck
        self.authenticate = authenticate; self.markerDirectory = markerDirectory; self.pipeCheck = pipeCheck
        self.backupCheck = backupCheck
    }
    #endif

    func execute(_ request: Request) throws -> [String: Any] {
        let account = try accountReader()
        let markers = MarkerStore(directory: try markerDirectory(account), account: account, backupCheck: backupCheck)
        let quietContext = try NativePresence.context(requirePresence: false)
        defer { quietContext.invalidate() }
        return try markers.withLock(create: request.op == "initialize") {
            var installation = try markers.load()
            if let expected = request.expectedInstallationID {
                guard installation?.id == expected else { throw Failure("installation-changed") }
            }
            var presenceContext: LAContext?
            defer { presenceContext?.invalidate() }
            if installation == nil {
                guard request.op == "initialize" else { throw Failure("installation-missing") }
                guard consoleCheck(account) else { throw Failure("locked") }
                if request.presence { presenceContext = try authenticate(true) }
                try recheckAccount(account)
                guard consoleCheck(account) else { throw Failure("locked") }
                let fresh = try Installation.fresh(account: account)
                // No Keychain read/enumeration when the marker is absent. A failure
                // can leave an unreachable namespace, never a revived old one.
                try keys.createNamespace(fresh, context: presenceContext ?? quietContext)
                try recheckAccount(account)
                try markers.publish(fresh)
                installation = fresh
            }
            guard let installation else { throw Failure("installation-missing") }
            try markers.recheck(installation)
            try recheckAccount(account)
            if request.op == "reset" {
                guard request.presence else { throw Failure("presence-required") }
                guard consoleCheck(account) else { throw Failure("locked") }
                presenceContext = try authenticate(true)
                try recheckAccount(account)
                guard consoleCheck(account) else { throw Failure("locked") }
                try markers.reset(installation)
                try recheckAccount(account)
                // installation_id identifies the invalidated namespace here.
                return ["ok": true, "installation_id": installation.idHex, "reset": true]
            }
            var locked = try isLocked(account, installation: installation, context: quietContext)
            if request.presence && presenceContext == nil {
                guard !locked else { throw Failure("locked") }
                presenceContext = try authenticate(true)
                try markers.recheck(installation)
                try recheckAccount(account)
                locked = try isLocked(account, installation: installation, context: quietContext)
            }
            if request.op == "account" || request.op == "initialize" {
                try markers.recheck(installation)
                try recheckAccount(account)
                return ["ok": true, "platform": "macos", "guid_values": account.guidValues,
                        "unique_id_values": account.uniqueIDValues, "uid": account.uid,
                        "installation_id": installation.idHex, "locked": locked]
            }
            guard !locked else { throw Failure("locked") }
            let context = presenceContext ?? quietContext
            var fields = try operate(request, installation: installation, context: context)
            // A marker removal, account transition or lock during an operation
            // suppresses the result (including signatures and unwrapped secrets).
            try markers.recheck(installation)
            try recheckAccount(account)
            guard try !isLocked(account, installation: installation, context: quietContext) else { throw Failure("locked") }
            fields["ok"] = true
            fields["installation_id"] = installation.idHex
            return fields
        }
    }

    private func recheckAccount(_ before: NativeAccount) throws {
        let after = try accountReader()
        guard before.uid == after.uid && before.bindingDigest == after.bindingDigest else { throw Failure("account-changed") }
    }

    private func isLocked(_ account: NativeAccount, installation: Installation, context: LAContext) throws -> Bool {
        guard consoleCheck(account) else { return true }
        do {
            guard try keys.namespace(installation, context: context) == installation.namespaceValue else { throw Failure("installation-invalid") }
            return false
        } catch let error as Failure where error.code == "locked" { return true }
    }

    private func operate(_ request: Request, installation: Installation, context: LAContext) throws -> [String: Any] {
        guard let slot = request.slot else { throw Failure("invalid-request") }
        switch request.op {
        case "generate":
            guard let kind = request.kind else { throw Failure("invalid-request") }
            var bytes: Data
            let metadata: StoredKey
            if kind == "ed25519" {
                let key = Curve25519.Signing.PrivateKey()
                bytes = key.rawRepresentation
                metadata = StoredKey(kind: kind, publicKey: key.publicKey.rawRepresentation)
            } else {
                bytes = try Installation.random32()
                metadata = StoredKey(kind: kind, publicKey: nil)
            }
            defer { bytes.resetBytes(in: 0..<bytes.count) }
            let ciphertext = try installation.seal(bytes, slot: slot, metadata: metadata)
            try keys.put(installation, slot: slot, metadata: metadata, data: ciphertext, replace: request.replace, context: context)
            return ["public_key": metadata.publicKey.map(Hex.encode) as Any? ?? NSNull()]
        case "wrap-secret":
            guard let bytes = request.data, bytes.count == 32, Request.secretSlots.contains(slot) else { throw Failure("invalid-request") }
            try pipeCheck()
            let metadata = StoredKey(kind: "secret32", publicKey: nil)
            let ciphertext = try installation.seal(bytes, slot: slot, metadata: metadata)
            try keys.put(installation, slot: slot, metadata: metadata, data: ciphertext, replace: false, context: context)
            return [:]
        case "public-key", "contains", "sign", "unwrap-secret", "delete":
            let metadata = try keys.metadata(installation, slot: slot, context: context)
            if let metadata {
                guard (metadata.kind == "secret32") == Request.secretSlots.contains(slot),
                      request.kind == nil || request.kind == metadata.kind else { throw Failure("key-kind-mismatch") }
            }
            if request.op == "contains" { return ["contains": metadata != nil] }
            if request.op == "public-key" { return ["public_key": metadata?.publicKey.map(Hex.encode) as Any? ?? NSNull()] }
            if request.op == "delete" { try keys.delete(installation, slot: slot, context: context); return [:] }
            guard let metadata else { throw Failure("key-missing") }
            if request.op == "unwrap-secret" {
                guard metadata.kind == "secret32", Request.secretSlots.contains(slot) else { throw Failure("key-kind-mismatch") }
                try pipeCheck()
            } else {
                guard metadata.kind == "ed25519", request.data != nil else { throw Failure("key-kind-mismatch") }
                if slot != "writer-signing" && !request.presence { throw Failure("presence-required") }
            }
            let ciphertext = try keys.read(installation, slot: slot, context: context)
            var bytes = try installation.open(ciphertext, slot: slot, metadata: metadata)
            defer { bytes.resetBytes(in: 0..<bytes.count) }
            guard bytes.count == 32 else { throw Failure("key-invalid") }
            if request.op == "unwrap-secret" { return ["secret": Hex.encode(bytes)] }
            do {
                let key = try Curve25519.Signing.PrivateKey(rawRepresentation: bytes)
                guard key.publicKey.rawRepresentation == metadata.publicKey else { throw Failure("key-invalid") }
                return ["signature": Hex.encode(try key.signature(for: request.data!))]
            } catch let failure as Failure { throw failure }
            catch { throw Failure("crypto-failed") }
        default: throw Failure("invalid-request")
        }
    }
}
