package com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.conscrypt.Conscrypt;

import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CryptoHelper {
    
    static {
        // Add BouncyCastle and Conscrypt providers
        Security.addProvider(new BouncyCastleProvider());
        Security.insertProviderAt(Conscrypt.newProvider(), 1);
    }
    
    public static void demonstrateCrypto() throws Exception {
        // AES encryption with Conscrypt
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        
        byte[] plaintext = "Hello, BUCK World!".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        System.out.println("AES-GCM encryption successful!");
        
        // RSA with BouncyCastle
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA", "BC");
        rsaKeyGen.initialize(2048);
        KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
        
        System.out.println("RSA 2048-bit key pair generated with BouncyCastle!");
    }
    
    public static void main(String[] args) {
        try {
            demonstrateCrypto();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}