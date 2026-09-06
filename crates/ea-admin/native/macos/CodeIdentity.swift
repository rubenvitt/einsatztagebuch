import Foundation
import Security
import Darwin

enum CodeIdentity {
    static let helper = "org.einsatzarchiv.operator.native"
    static let monitor = "org.einsatzarchiv.operator.monitor"
    static let parent = "org.einsatzarchiv.cli"

    static func ownTeam(identifier: String) throws -> String {
        var value: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &value) == errSecSuccess, let value else { throw Failure("code-identity-invalid") }
        let info = try validate(value, requirement: "anchor apple generic and identifier \"\(identifier)\"")
        guard let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
              team.count == 10, team.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }) else {
            throw Failure("code-identity-invalid")
        }
        return team
    }

    static func peer(_ socket: Int32, identifier: String, team: String, root: Bool) throws {
        var uid: uid_t = 0
        var gid: gid_t = 0
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getpeereid(socket, &uid, &gid) == 0, (!root || uid == 0),
              getsockopt(socket, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0,
              size == MemoryLayout<pid_t>.size, pid > 0 else { throw Failure("code-identity-invalid") }
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(), &code) == errSecSuccess, let code else {
            throw Failure("code-identity-invalid")
        }
        _ = try validate(code, requirement: "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"\(team)\"")
        // Confirm the connected endpoint still belongs to the validated PID.
        var after: pid_t = 0
        guard getsockopt(socket, SOL_LOCAL, LOCAL_PEERPID, &after, &size) == 0, after == pid else { throw Failure("code-identity-invalid") }
    }

    private static func validate(_ code: SecCode, requirement text: String) throws -> [String: Any] {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(), &requirement) == errSecSuccess,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw Failure("code-identity-invalid")
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode,
              SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw Failure("code-identity-invalid")
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any], let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
              flags.uint32Value & SecCodeSignatureFlags.runtime.rawValue != 0 else { throw Failure("code-identity-invalid") }
        let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        for key in ["com.apple.security.get-task-allow", "get-task-allow", "com.apple.security.cs.disable-library-validation",
                    "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.allow-unsigned-executable-memory",
                    "com.apple.security.cs.allow-jit", "com.apple.security.cs.disable-executable-page-protection"] {
            if (entitlements[key] as? NSNumber)?.boolValue == true { throw Failure("code-identity-invalid") }
        }
        guard SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else {
            throw Failure("code-identity-invalid")
        }
        return info
    }
}
