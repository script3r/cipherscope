import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun main() {
    val key = "secret_key".toByteArray()
    val message = "Hello, World!".toByteArray()
    
    // Create HMAC
    val mac = Mac.getInstance("HmacSHA256")
    val keySpec = SecretKeySpec(key, "HmacSHA256")
    mac.init(keySpec)
    val hmac = mac.doFinal(message)
    
    // Verify HMAC
    val verifier = Mac.getInstance("HmacSHA256")
    verifier.init(keySpec)
    val expectedHmac = verifier.doFinal(message)
}
