import org.conscrypt.Conscrypt;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;

public class CryptoUtils {
    static {
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
    }
    
    public static void performAesEncryption() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        byte[] plaintext = "Module1: AES-256-GCM".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        System.out.println("Module1: AES-256-GCM encryption successful");
    }
}