import CryptoKit
import Foundation

let plaintext = "Hello, World!".data(using: .utf8)!

// Generate key
let key = SymmetricKey(size: .bits256)

// Encrypt
let sealedBox = try! AES.GCM.seal(plaintext, using: key)

// Decrypt
let decrypted = try! AES.GCM.open(sealedBox, using: key)
