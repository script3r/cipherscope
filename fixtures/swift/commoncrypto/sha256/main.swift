import Foundation
import CommonCrypto

let message = "Hello, World!".data(using: .utf8)!
var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))

message.withUnsafeBytes { bytes in
    CC_SHA256(bytes.baseAddress, CC_LONG(message.count), &digest)
}
