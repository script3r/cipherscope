import com.google.crypto.tink.Mac;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.mac.MacKeyTemplates;

public class Main {
    public static void main(String[] args) throws Exception {
        MacConfig.register();
        
        // Generate key
        KeysetHandle keysetHandle = KeysetHandle.generateNew(
            MacKeyTemplates.HMAC_SHA256_256BITTAG);
        
        // Get primitive
        Mac mac = keysetHandle.getPrimitive(Mac.class);
        
        byte[] message = "Hello, World!".getBytes();
        
        // Create MAC
        byte[] tag = mac.computeMac(message);
        
        // Verify MAC
        mac.verifyMac(tag, message);
    }
}
