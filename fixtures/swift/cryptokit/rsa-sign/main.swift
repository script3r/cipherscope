import CryptoKit
import Foundation

// Note: CryptoKit doesn't support RSA directly, using P256 as an alternative
let message = "Hello, World!".data(using: .utf8)!

// Generate key pair
let privateKey = P256.Signing.PrivateKey()
let publicKey = privateKey.publicKey

// Sign
let signature = try! privateKey.signature(for: message)

// Verify
let isValid = publicKey.isValidSignature(signature, for: message)
