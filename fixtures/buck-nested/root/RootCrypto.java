import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;

public class RootCrypto {
    public static void initializeCrypto() {
        Security.addProvider(new BouncyCastleProvider());
        
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            System.out.println("Root: RSA 2048-bit key pair generated");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}