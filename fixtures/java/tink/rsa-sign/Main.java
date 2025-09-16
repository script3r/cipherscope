import com.google.crypto.tink.signature.PublicKeySign;
import com.google.crypto.tink.signature.PublicKeyVerify;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.signature.SignatureKeyTemplates;

public class Main {
    public static void main(String[] args) throws Exception {
        SignatureConfig.register();
        
        // Generate key pair
        KeysetHandle privateKeysetHandle = KeysetHandle.generateNew(
            SignatureKeyTemplates.RSA_PSS_3072_SHA256_F4);
        KeysetHandle publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();
        
        // Get primitives
        PublicKeySign signer = privateKeysetHandle.getPrimitive(PublicKeySign.class);
        PublicKeyVerify verifier = publicKeysetHandle.getPrimitive(PublicKeyVerify.class);
        
        byte[] message = "Hello, World!".getBytes();
        
        // Sign
        byte[] signature = signer.sign(message);
        
        // Verify
        verifier.verify(signature, message);
    }
}
