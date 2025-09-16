import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        byte[] key = "secret_key".getBytes();
        byte[] message = "Hello, World!".getBytes();
        
        // Create HMAC
        Mac mac = Mac.getInstance("HmacSHA256", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(keySpec);
        byte[] hmac = mac.doFinal(message);
        
        // Verify HMAC (compare with expected)
        Mac verifier = Mac.getInstance("HmacSHA256", "BC");
        verifier.init(keySpec);
        byte[] expectedHmac = verifier.doFinal(message);
    }
}
