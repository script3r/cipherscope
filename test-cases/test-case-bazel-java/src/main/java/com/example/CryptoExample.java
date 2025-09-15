package com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.AeadConfig;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;

import java.security.*;
import javax.crypto.Cipher;

public class CryptoExample {
    public static void main(String[] args) throws Exception {
        // Add BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
        
        // Initialize Tink
        AeadConfig.register();
        
        // Generate AES-GCM key with Tink
        KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
        Aead aead = keysetHandle.getPrimitive(Aead.class);
        
        // Test message
        byte[] plaintext = "Hello, Bazel World!".getBytes();
        byte[] associatedData = "example".getBytes();
        
        // Encrypt
        byte[] ciphertext = aead.encrypt(plaintext, associatedData);
        
        // Decrypt
        byte[] decrypted = aead.decrypt(ciphertext, associatedData);
        
        System.out.println("Original: " + new String(plaintext));
        System.out.println("Decrypted: " + new String(decrypted));
        
        // RSA with BouncyCastle
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        System.out.println("RSA 2048-bit key pair generated with BouncyCastle!");
    }
}