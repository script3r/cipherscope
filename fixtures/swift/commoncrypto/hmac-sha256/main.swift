import Foundation
import CommonCrypto

let key = "secret_key".data(using: .utf8)!
let message = "Hello, World!".data(using: .utf8)!
var mac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))

key.withUnsafeBytes { keyBytes in
    message.withUnsafeBytes { messageBytes in
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),
               keyBytes.baseAddress, key.count,
               messageBytes.baseAddress, message.count,
               &mac)
    }
}
