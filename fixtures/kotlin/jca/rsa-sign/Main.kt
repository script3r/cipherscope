import java.security.KeyPairGenerator
import java.security.Signature

fun main() {
    val message = "Hello, World!".toByteArray()
    
    // Generate RSA key pair
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(2048)
    val keyPair = keyGen.generateKeyPair()
    
    // Sign
    val signer = Signature.getInstance("SHA256withRSA")
    signer.initSign(keyPair.private)
    signer.update(message)
    val signature = signer.sign()
    
    // Verify
    val verifier = Signature.getInstance("SHA256withRSA")
    verifier.initVerify(keyPair.public)
    verifier.update(message)
    val valid = verifier.verify(signature)
}
