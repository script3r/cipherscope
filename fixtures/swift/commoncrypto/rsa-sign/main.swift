import Foundation
import Security

let message = "Hello, World!".data(using: .utf8)!

// Generate RSA key pair
let parameters: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecAttrKeySizeInBits as String: 2048
]

var publicKey, privateKey: SecKey?
SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)

// Sign
var error: Unmanaged<CFError>?
let signature = SecKeyCreateSignature(
    privateKey!,
    .rsaSignatureMessagePSSSHA256,
    message as CFData,
    &error
)

// Verify
let valid = SecKeyVerifySignature(
    publicKey!,
    .rsaSignatureMessagePSSSHA256,
    message as CFData,
    signature!,
    &error
)
