import java.security.MessageDigest;

public class Main {
    public static void main(String[] args) throws Exception {
        byte[] message = "Hello, World!".getBytes();
        
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(message);
    }
}
