import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom

fun main() {
    // Generate key and IV
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(256)
    val key = keyGen.generateKey()
    
    val iv = ByteArray(12)
    SecureRandom().nextBytes(iv)
    
    val plaintext = "Hello, World!".toByteArray()
    
    // Encrypt
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
    val ciphertext = cipher.doFinal(plaintext)
    
    // Decrypt
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
    val decrypted = cipher.doFinal(ciphertext)
}
