import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;

public class JavaCrypto {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        System.out.println("Bazel Java Module: RSA 2048-bit key generated");
    }
}