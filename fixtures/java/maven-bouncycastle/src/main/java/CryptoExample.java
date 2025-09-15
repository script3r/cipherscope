import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import javax.crypto.Cipher;

public class CryptoExample {
    public static void main(String[] args) throws Exception {
        // Add BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
        
        // Generate RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // Test encryption/decryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        
        String message = "Hello, World!";
        byte[] messageBytes = message.getBytes();
        
        // Encrypt
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted = cipher.doFinal(messageBytes);
        
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(encrypted);
        
        System.out.println("Original: " + message);
        System.out.println("Decrypted: " + new String(decrypted));
    }
}