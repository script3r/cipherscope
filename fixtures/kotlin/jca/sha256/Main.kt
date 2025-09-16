import java.security.MessageDigest

fun main() {
    val message = "Hello, World!".toByteArray()
    
    val md = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(message)
}
