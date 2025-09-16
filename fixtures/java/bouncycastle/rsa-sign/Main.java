import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        // Generate key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // Sign
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(keyPair.getPrivate());
        byte[] message = "Hello, World!".getBytes();
        signature.update(message);
        byte[] sig = signature.sign();
        
        // Verify
        signature.initVerify(keyPair.getPublic());
        signature.update(message);
        boolean valid = signature.verify(sig);
    }
}
