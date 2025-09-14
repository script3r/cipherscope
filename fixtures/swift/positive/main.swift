import CryptoKit
import CommonCrypto

func main() {
    // CryptoKit usage
    let key = SymmetricKey(size: .bits256)
    let data = "Hello, World!".data(using: .utf8)!
    
    do {
        let sealedBox = try AES.GCM.seal(data, using: key)
        print("Encrypted: \(sealedBox)")
    } catch {
        print("Encryption failed: \(error)")
    }
    
    // CommonCrypto usage
    let message = "Test message"
    let messageData = message.data(using: .utf8)!
    var digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
    
    _ = digest.withUnsafeMutableBytes { digestBytes in
        messageData.withUnsafeBytes { messageBytes in
            CC_SHA256(messageBytes.baseAddress, CC_LONG(messageData.count), digestBytes.bindMemory(to: UInt8.self).baseAddress)
        }
    }
    
    print("SHA256: \(digest.map { String(format: "%02hhx", $0) }.joined())")
}
