import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

public class JcaExample {
    public static void main(String[] args) throws Exception {
        // RSA key generation using standard JCA
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
        
        // AES key generation
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256);
        SecretKey aesKey = aesKeyGen.generateKey();
        
        // AES-GCM encryption
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        
        byte[] plaintext = "Hello, JCA World!".getBytes();
        byte[] ciphertext = aesCipher.doFinal(plaintext);
        
        // SHA-256 hashing
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(plaintext);
        
        // ECDSA key generation
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        ecKeyGen.initialize(256); // P-256 curve
        KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
        
        // ECDSA signature
        Signature ecdsaSignature = Signature.getInstance("SHA256withECDSA");
        ecdsaSignature.initSign(ecKeyPair.getPrivate());
        ecdsaSignature.update(plaintext);
        byte[] signature = ecdsaSignature.sign();
        
        System.out.println("JCA/JCE crypto operations completed:");
        System.out.println("- RSA 2048-bit key pair generated");
        System.out.println("- AES-256-GCM encryption performed");
        System.out.println("- SHA-256 hash computed");
        System.out.println("- ECDSA P-256 signature created");
    }
}