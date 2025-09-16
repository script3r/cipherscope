import CryptoKit
import Foundation

let message = "Hello, World!".data(using: .utf8)!

let digest = SHA256.hash(data: message)
