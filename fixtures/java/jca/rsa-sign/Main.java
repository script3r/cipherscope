import java.security.*;

public class Main {
    public static void main(String[] args) throws Exception {
        byte[] message = "Hello, World!".getBytes();
        
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // Sign
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();
        
        // Verify
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        boolean valid = verifier.verify(signature);
    }
}
