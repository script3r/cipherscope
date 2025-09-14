import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.MessageDigest
import java.security.Security

fun main() {
    // Java Crypto API usage
    val keyGenerator = KeyGenerator.getInstance("AES")
    val secretKey = keyGenerator.generateKey()
    
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    
    val plaintext = "Hello, World!".toByteArray()
    val ciphertext = cipher.doFinal(plaintext)
    
    println("Encrypted: ${ciphertext.joinToString("") { "%02x".format(it) }}")
    
    // BouncyCastle usage
    Security.addProvider(BouncyCastleProvider())
    
    val messageDigest = MessageDigest.getInstance("SHA-256")
    val hash = messageDigest.digest(plaintext)
    
    println("SHA-256: ${hash.joinToString("") { "%02x".format(it) }}")
    
    // Korlibs Krypto usage (Kotlin Multiplatform)
    // Note: This would typically be in a multiplatform project
    // import com.soywiz.krypto.encoding.hex
    // import com.soywiz.krypto.hash.sha256
    // val kryptoHash = plaintext.sha256().hex
    // println("Krypto SHA-256: $kryptoHash")
}
