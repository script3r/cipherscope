import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import java.security.GeneralSecurityException;

public class TinkExample {
    public static void main(String[] args) throws GeneralSecurityException {
        // Register AEAD configuration
        AeadConfig.register();
        
        // Generate a new AES-GCM key
        KeysetHandle keysetHandle = KeysetHandle.generateNew(
            AeadKeyTemplates.AES256_GCM);
        
        // Get the primitive
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        
        // Encrypt data
        byte[] plaintext = "Hello Tink".getBytes();
        byte[] associatedData = "metadata".getBytes();
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);
        
        // Decrypt data
        byte[] decrypted = aead.decrypt(ciphertext, associatedData);
        System.out.println(new String(decrypted));
    }
}
