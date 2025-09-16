import com.google.crypto.tink.prf.Prf;
import com.google.crypto.tink.prf.PrfConfig;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.prf.PrfKeyTemplates;

public class Main {
    public static void main(String[] args) throws Exception {
        // Note: Tink doesn't have direct hash support, using PRF as alternative
        PrfConfig.register();
        
        KeysetHandle keysetHandle = KeysetHandle.generateNew(
            PrfKeyTemplates.HMAC_SHA256_PRF);
        
        Prf prf = keysetHandle.getPrimitive(Prf.class);
        
        byte[] input = "Hello, World!".getBytes();
        byte[] output = prf.compute(input, 32);
    }
}
