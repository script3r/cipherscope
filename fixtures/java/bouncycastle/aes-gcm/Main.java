import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.Security;
import java.security.SecureRandom;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        // Generate key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        
        // Generate IV
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decrypted = cipher.doFinal(ciphertext);
    }
}
