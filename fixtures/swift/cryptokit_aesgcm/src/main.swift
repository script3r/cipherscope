import CryptoKit
import Foundation

let key = SymmetricKey(size: .bits256)
let nonce = AES.GCM.Nonce()
let sealed = try! AES.GCM.seal(Data("hello".utf8), using: key, nonce: nonce)
print(sealed.ciphertext.count)
