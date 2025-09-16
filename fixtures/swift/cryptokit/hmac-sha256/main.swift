import CryptoKit
import Foundation

let key = SymmetricKey(data: "secret_key".data(using: .utf8)!)
let message = "Hello, World!".data(using: .utf8)!

// Create and verify HMAC
let mac = HMAC<SHA256>.authenticationCode(for: message, using: key)
let isValid = HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: message, using: key)
