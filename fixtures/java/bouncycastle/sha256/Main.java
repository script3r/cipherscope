import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.MessageDigest;
import java.security.Security;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256", "BC");
        byte[] message = "Hello, World!".getBytes();
        byte[] hash = digest.digest(message);
    }
}
