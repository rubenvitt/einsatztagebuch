import Foundation
import OpenDirectory
import CryptoKit
import CoreGraphics
import LocalAuthentication
import Darwin

struct NativeAccount: Equatable {
    let uid: uid_t
    let guidValues: [String]
    let uniqueIDValues: [String]
    let bindingDigest: Data

    static func read() throws -> NativeAccount {
        let uid = getuid()
        guard uid != UInt32.max, geteuid() == uid, getgid() == getegid() else { throw Failure("account-invalid") }
        do {
            let node = try ODNode(session: ODSession.default(), type: UInt32(kODNodeTypeAuthentication))
            let attributes = [kODAttributeTypeGUID, kODAttributeTypeUniqueID]
            let query = try ODQuery(node: node, forRecordTypes: kODRecordTypeUsers,
                                    attribute: kODAttributeTypeUniqueID, matchType: ODMatchType(kODMatchEqualTo),
                                    queryValues: String(uid), returnAttributes: attributes, maximumResults: 2)
            guard let records = try query.resultsAllowingPartial(false) as? [ODRecord], records.count == 1 else { throw Failure("account-invalid") }
            // Both attributes are read in one details call on the exact queried record.
            let details = try records[0].recordDetails(forAttributes: attributes)
            guard let guids = details[kODAttributeTypeGUID] as? [String],
                  let ids = details[kODAttributeTypeUniqueID] as? [String],
                  getuid() == uid, geteuid() == uid else { throw Failure("account-invalid") }
            return try validate(guidValues: guids, uniqueIDValues: ids, uid: uid)
        } catch let failure as Failure { throw failure }
        catch { throw Failure("account-unavailable") }
    }

    static func validate(guidValues: [String], uniqueIDValues: [String], uid: uid_t) throws -> NativeAccount {
        guard uid != UInt32.max, guidValues.count == 1, uniqueIDValues == [String(uid)] else { throw Failure("account-invalid") }
        let bytes = Array(guidValues[0].utf8)
        guard bytes.count == 36 else { throw Failure("account-invalid") }
        var compact = [UInt8]()
        for (i, byte) in bytes.enumerated() {
            if [8, 13, 18, 23].contains(i) { guard byte == 45 else { throw Failure("account-invalid") } }
            else {
                guard (48...57).contains(byte) || (65...70).contains(byte) || (97...102).contains(byte) else { throw Failure("account-invalid") }
                compact.append((65...70).contains(byte) ? byte + 32 : byte)
            }
        }
        let guid = try Hex.decode(String(decoding: compact, as: UTF8.self))
        guard guid.contains(where: { $0 != 0 }) else { throw Failure("account-invalid") }
        // Internal native-store binding, not the archive os-account-context hash.
        var input = Data("EINSATZARCHIV-NATIVE-MACOS-ACCOUNT-v1\0".utf8)
        input.append(guid)
        input.append(contentsOf: [UInt8(uid >> 24), UInt8((uid >> 16) & 255), UInt8((uid >> 8) & 255), UInt8(uid & 255)])
        return NativeAccount(uid: uid, guidValues: guidValues, uniqueIDValues: uniqueIDValues,
                             bindingDigest: Data(SHA256.hash(data: input)))
    }

    func fixedMarkerDirectory() throws -> URL {
        var record = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buffer = [CChar](repeating: 0, count: 16_384)
        guard getpwuid_r(uid, &record, &buffer, buffer.count, &result) == 0,
              result != nil, record.pw_uid == uid, let directory = record.pw_dir else { throw Failure("account-unavailable") }
        let home = String(cString: directory)
        guard home.hasPrefix("/"), home != "/", getuid() == uid, geteuid() == uid else { throw Failure("account-invalid") }
        return URL(fileURLWithPath: home, isDirectory: true)
            .appendingPathComponent("Library/Application Support/Einsatzarchiv/NativeOperator", isDirectory: true)
    }

    func hasActiveConsole() -> Bool {
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any],
              let user = session[kCGSessionUserIDKey as String] as? NSNumber,
              let console = session[kCGSessionOnConsoleKey as String] as? Bool,
              let login = session[kCGSessionLoginDoneKey as String] as? Bool else { return false }
        return user.uint32Value == uid && console && login && getuid() == uid && geteuid() == uid
    }
}

enum NativePresence {
    private final class ResultBox: @unchecked Sendable {
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        private var value = "presence-failed"
        func complete(_ success: Bool, _ error: (any Error)?) {
            lock.lock()
            if success { value = "ok" }
            else if let error = error as? LAError, [.userCancel, .appCancel, .systemCancel].contains(error.code) { value = "presence-cancelled" }
            lock.unlock()
            semaphore.signal()
        }
        func result() -> String { lock.lock(); defer { lock.unlock() }; return value }
    }

    static func context(requirePresence: Bool) throws -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.interactionNotAllowed = !requirePresence
        guard requirePresence else { return context }
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { throw Failure("presence-unavailable") }
        let box = ResultBox()
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Authenticate to use Einsatzarchiv keys.") { success, error in
            box.complete(success, error)
        }
        guard box.semaphore.wait(timeout: .now() + 45) == .success else {
            context.invalidate()
            throw Failure("presence-timeout")
        }
        let result = box.result()
        guard result == "ok" else { context.invalidate(); throw Failure(result) }
        // Any following SecItem request may reuse this one fresh authentication,
        // but cannot present a second, implicit dialog.
        context.interactionNotAllowed = true
        return context
    }
}
