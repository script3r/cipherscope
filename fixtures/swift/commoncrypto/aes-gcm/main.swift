import Foundation
import CryptoKit

// Note: CommonCrypto doesn't support AES-GCM directly, using CryptoKit
let key = SymmetricKey(size: .bits256)
let plaintext = "Hello, World!".data(using: .utf8)!

// Encrypt
let sealedBox = try! AES.GCM.seal(plaintext, using: key)

// Decrypt
let decrypted = try! AES.GCM.open(sealedBox, using: key)
