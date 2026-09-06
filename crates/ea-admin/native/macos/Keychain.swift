import Foundation
import Security
import CryptoKit
import LocalAuthentication

struct StoredKey {
    let kind: String
    let publicKey: Data?
    var metadata: Data { Data([1, kind == "ed25519" ? 1 : 2]) + (publicKey ?? Data()) }
    static func decode(_ data: Data) throws -> StoredKey {
        if data.count == 34 && data.prefix(2) == Data([1, 1]) { return StoredKey(kind: "ed25519", publicKey: Data(data.dropFirst(2))) }
        if data == Data([1, 2]) { return StoredKey(kind: "secret32", publicKey: nil) }
        throw Failure("key-invalid")
    }
}

protocol NativeKeyStore {
    func namespace(_ installation: Installation, context: LAContext) throws -> Data?
    func createNamespace(_ installation: Installation, context: LAContext) throws
    func metadata(_ installation: Installation, slot: String, context: LAContext) throws -> StoredKey?
    func read(_ installation: Installation, slot: String, context: LAContext) throws -> Data
    func put(_ installation: Installation, slot: String, metadata: StoredKey, data: Data, replace: Bool, context: LAContext) throws
    func delete(_ installation: Installation, slot: String, context: LAContext) throws
}

final class KeychainStore: NativeKeyStore {
    private let namespaceSlot = "__installation"

    private func query(_ installation: Installation, slot: String, context: LAContext) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: installation.service,
         kSecAttrAccount as String: slot,
         kSecAttrSynchronizable as String: false,
         kSecUseDataProtectionKeychain as String: true,
         kSecUseAuthenticationContext as String: context]
    }

    private func matchingQuery(_ installation: Installation, slot: String, context: LAContext) -> [String: Any] {
        var item = query(installation, slot: slot, context: context)
        // Accessibility is a matching attribute, not a wildcard: a downgraded
        // sentinel must never make account.locked incorrectly report false.
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        return item
    }

    private func check(_ status: OSStatus) throws {
        switch status {
        case errSecSuccess: return
        case errSecDuplicateItem: throw Failure("key-exists")
        case errSecItemNotFound: throw Failure("key-missing")
        case errSecInteractionNotAllowed: throw Failure("locked")
        case errSecUserCanceled: throw Failure("presence-cancelled")
        case errSecAuthFailed: throw Failure("presence-failed")
        case errSecMissingEntitlement: throw Failure("keychain-entitlement")
        default: throw Failure("keychain-unavailable")
        }
    }

    func namespace(_ installation: Installation, context: LAContext) throws -> Data? {
        do { return try read(installation, slot: namespaceSlot, context: context) }
        catch let error as Failure where error.code == "key-missing" { return nil }
    }

    func createNamespace(_ installation: Installation, context: LAContext) throws {
        var item = query(installation, slot: namespaceSlot, context: context)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        item[kSecValueData as String] = installation.namespaceValue
        try check(SecItemAdd(item as CFDictionary, nil))
    }

    func metadata(_ installation: Installation, slot: String, context: LAContext) throws -> StoredKey? {
        var item = matchingQuery(installation, slot: slot, context: context)
        item[kSecMatchLimit as String] = kSecMatchLimitOne
        item[kSecReturnAttributes as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(item as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status)
        // The exact query already constrains non-sync and accessibility; optional
        // returned attributes may be omitted by Security when their value is empty.
        guard let attributes = result as? [String: Any], let data = attributes[kSecAttrGeneric as String] as? Data else { throw Failure("key-invalid") }
        return try StoredKey.decode(data)
    }

    func read(_ installation: Installation, slot: String, context: LAContext) throws -> Data {
        var item = matchingQuery(installation, slot: slot, context: context)
        item[kSecMatchLimit as String] = kSecMatchLimitOne
        item[kSecReturnData as String] = true
        var result: CFTypeRef?
        try check(SecItemCopyMatching(item as CFDictionary, &result))
        guard let data = result as? Data else { throw Failure("key-invalid") }
        return data
    }

    func put(_ installation: Installation, slot: String, metadata: StoredKey, data: Data, replace: Bool, context: LAContext) throws {
        guard data.count == 60 else { throw Failure("key-invalid") }
        var item = query(installation, slot: slot, context: context)
        let requiresPresence = metadata.kind == "ed25519" && slot != "writer-signing"
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                         requiresPresence ? .userPresence : [], &accessError) else {
            throw Failure("keychain-unavailable")
        }
        item[kSecAttrAccessControl as String] = access
        item[kSecAttrGeneric as String] = metadata.metadata
        item[kSecValueData as String] = data
        let status = SecItemAdd(item as CFDictionary, nil)
        if status == errSecDuplicateItem && replace {
            guard slot == "operator-instance", metadata.kind == "ed25519" else { throw Failure("invalid-request") }
            // Only explicit operator replacement may update; generation is otherwise
            // atomic exclusive SecItemAdd, with no search-then-overwrite race.
            let update: [String: Any] = [kSecValueData as String: data,
                                         kSecAttrGeneric as String: metadata.metadata,
                                         kSecAttrAccessControl as String: access]
            try check(SecItemUpdate(matchingQuery(installation, slot: slot, context: context) as CFDictionary, update as CFDictionary))
        } else { try check(status) }
    }

    func delete(_ installation: Installation, slot: String, context: LAContext) throws {
        let status = SecItemDelete(matchingQuery(installation, slot: slot, context: context) as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }
}
