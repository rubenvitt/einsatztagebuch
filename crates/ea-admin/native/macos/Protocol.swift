import Foundation
import Darwin

struct Failure: Error, Sendable {
    let code: String
    init(_ code: String) { self.code = code }
}

enum Hex {
    static func encode(_ data: Data) -> String {
        let digits = Array("0123456789abcdef".utf8)
        return String(decoding: data.flatMap { [digits[Int($0 >> 4)], digits[Int($0 & 15)]] }, as: UTF8.self)
    }
    static func decode(_ text: String) throws -> Data {
        let bytes = Array(text.utf8)
        guard bytes.count % 2 == 0 else { throw Failure("invalid-request") }
        func nibble(_ byte: UInt8) throws -> UInt8 {
            switch byte {
            case 48...57: return byte - 48
            case 97...102: return byte - 87
            default: throw Failure("invalid-request")
            }
        }
        var data = Data(capacity: bytes.count / 2)
        for i in stride(from: 0, to: bytes.count, by: 2) {
            try data.append(nibble(bytes[i]) << 4 | nibble(bytes[i + 1]))
        }
        return data
    }
}

struct Request {
    let op: String
    let slot: String?
    let kind: String?
    let data: Data?
    let presence: Bool
    let replace: Bool
    let expectedInstallationID: Data?
    static let maximumBytes = 65_536
    static let secretSlots: Set<String> = ["database-key", "draft-key"]

    static func parseChallenge(_ bytes: Data) throws -> String {
        guard bytes.count < 1024 else { throw Failure("invalid-request") }
        var parser = FlatObjectParser(bytes: Array(bytes))
        let object = try parser.parse()
        guard Set(object.keys) == ["challenge"], let challenge = object["challenge"] as? String,
              challenge.utf8.count == 64, try Hex.decode(challenge).count == 32 else { throw Failure("invalid-request") }
        return challenge
    }

    static func parse(_ bytes: Data) throws -> Request {
        guard bytes.count <= maximumBytes else { throw Failure("request-too-large") }
        var parser = FlatObjectParser(bytes: Array(bytes))
        let object = try parser.parse()
        guard let op = object["op"] as? String else { throw Failure("invalid-request") }
        let readOnly: Set<String> = ["account", "public-key", "contains"]
        var allowed: Set<String> = ["op", "presence", "installation_id"]
        switch op {
        case "account", "initialize", "reset": break
        case "watch-session": allowed = ["op", "installation_id"]
        case "generate": allowed.formUnion(["slot", "kind", "replace"])
        case "sign", "wrap-secret": allowed.formUnion(["slot", "kind", "data"])
        case "public-key", "unwrap-secret", "delete", "contains": allowed.formUnion(["slot", "kind"])
        default: throw Failure("invalid-request")
        }
        guard Set(object.keys).isSubset(of: allowed) else { throw Failure("invalid-request") }
        guard object["presence"] == nil || object["presence"] is Bool,
              object["replace"] == nil || object["replace"] is Bool else { throw Failure("invalid-request") }
        let presence = object["presence"] as? Bool ?? false
        let replace = object["replace"] as? Bool ?? false
        var expectedInstallationID: Data?
        if object["installation_id"] != nil {
            guard let text = object["installation_id"] as? String else { throw Failure("invalid-request") }
            expectedInstallationID = try Hex.decode(text)
            guard expectedInstallationID?.count == 32 else { throw Failure("invalid-request") }
        }
        guard !(presence && readOnly.contains(op)) else { throw Failure("invalid-request") }
        if op == "watch-session" && expectedInstallationID == nil { throw Failure("invalid-request") }
        let slot = object["slot"] as? String
        let kind = object["kind"] as? String
        guard object["kind"] == nil || kind == "ed25519" || kind == "secret32" else { throw Failure("invalid-request") }
        if !["account", "initialize", "reset", "watch-session"].contains(op) {
            guard let slot, (1...64).contains(slot.utf8.count),
                  slot.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }) else {
                throw Failure("invalid-request")
            }
        }
        if op == "generate" && kind == nil { throw Failure("invalid-request") }
        if let slot, let kind {
            guard (kind == "secret32") == secretSlots.contains(slot) else { throw Failure("invalid-request") }
        }
        if op == "sign" {
            guard let slot, !secretSlots.contains(slot), kind == nil || kind == "ed25519" else { throw Failure("invalid-request") }
            if slot != "writer-signing" && !presence { throw Failure("presence-required") }
        }
        if op == "wrap-secret" || op == "unwrap-secret" {
            guard let slot, secretSlots.contains(slot), kind == nil || kind == "secret32" else { throw Failure("invalid-request") }
        }
        if replace {
            guard op == "generate", slot == "operator-instance", kind == "ed25519" else { throw Failure("invalid-request") }
            guard presence else { throw Failure("presence-required") }
        }
        if op == "reset" && !presence { throw Failure("presence-required") }
        var data: Data?
        if op == "sign" || op == "wrap-secret" {
            guard let value = object["data"] as? String else { throw Failure("invalid-request") }
            data = try Hex.decode(value)
            if op == "wrap-secret" && data?.count != 32 { throw Failure("invalid-request") }
        }
        return Request(op: op, slot: slot, kind: kind, data: data, presence: presence, replace: replace,
                       expectedInstallationID: expectedInstallationID)
    }
}

// A closed, flat JSON grammar. Foundation decodes only individual JSON strings;
// duplicate keys (including escaped spellings), nesting and coercions never pass.
private struct FlatObjectParser {
    let bytes: [UInt8]
    var position = 0
    mutating func whitespace() { while position < bytes.count && [9, 10, 13, 32].contains(bytes[position]) { position += 1 } }
    mutating func take(_ byte: UInt8) throws {
        whitespace()
        guard position < bytes.count && bytes[position] == byte else { throw Failure("invalid-request") }
        position += 1
    }
    mutating func string() throws -> String {
        whitespace()
        let start = position
        try take(34)
        while position < bytes.count {
            let byte = bytes[position]
            position += 1
            if byte == 34 {
                guard let value = try? JSONSerialization.jsonObject(with: Data(bytes[start..<position]), options: .fragmentsAllowed) as? String else {
                    throw Failure("invalid-request")
                }
                return value
            }
            guard byte >= 32 else { throw Failure("invalid-request") }
            if byte == 92 { position += 1 }
        }
        throw Failure("invalid-request")
    }
    mutating func parse() throws -> [String: Any] {
        try take(123)
        var result: [String: Any] = [:]
        whitespace()
        if position < bytes.count && bytes[position] != 125 {
            while true {
                let key = try string()
                guard result[key] == nil, result.count < 7 else { throw Failure("invalid-request") }
                try take(58)
                whitespace()
                if position < bytes.count && bytes[position] == 34 { result[key] = try string() }
                else if bytes[position...].starts(with: Array("true".utf8)) { result[key] = true; position += 4 }
                else if bytes[position...].starts(with: Array("false".utf8)) { result[key] = false; position += 5 }
                else { throw Failure("invalid-request") }
                whitespace()
                guard position < bytes.count else { throw Failure("invalid-request") }
                if bytes[position] == 125 { break }
                try take(44)
            }
        }
        try take(125)
        whitespace()
        guard position == bytes.count else { throw Failure("invalid-request") }
        return result
    }
}

enum Transport {
    static func readRequest() throws -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = Darwin.read(STDIN_FILENO, &buffer, min(buffer.count, Request.maximumBytes + 1 - data.count))
            if count < 0 { if errno == EINTR { continue }; throw Failure("io-failed") }
            if count == 0 {
                if (try? Request.parse(data).op) == "watch-session" { throw Failure("invalid-request") }
                return data
            }
            data.append(contentsOf: buffer.prefix(count))
            if data.count > Request.maximumBytes { throw Failure("request-too-large") }
            // Only watch-session is newline framed. Ordinary requests still
            // require EOF so an embedded newline cannot hide a second object.
            if let newline = data.firstIndex(of: 10),
               (try? Request.parse(Data(data[..<newline])).op) == "watch-session" {
                guard newline == data.count - 1 else { throw Failure("invalid-request") }
                return Data(data[..<newline])
            }
        }
    }
    static func requirePrivatePipes() throws {
        for fd in [STDIN_FILENO, STDOUT_FILENO] {
            var info = stat()
            guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFIFO, info.st_nlink == 0 else {
                throw Failure("protected-pipe-required")
            }
        }
    }
    static func writeResponse(_ response: [String: Any]) {
        guard var bytes = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]) else { return }
        bytes.append(10)
        bytes.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(STDOUT_FILENO, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { return }
                offset += count
            }
        }
    }
}
