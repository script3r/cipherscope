import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;

public class Main {
    public static void main(String[] args) throws Exception {
        AeadConfig.register();
        
        // Generate key
        KeysetHandle keysetHandle = KeysetHandle.generateNew(
            AeadKeyTemplates.AES256_GCM);
        
        // Get primitive
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        
        byte[] plaintext = "Hello, World!".getBytes();
        byte[] associatedData = new byte[0];
        
        // Encrypt
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);
        
        // Decrypt
        byte[] decrypted = aead.decrypt(ciphertext, associatedData);
    }
}
