import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.Base64;

public class ComprehensiveTest {
    
    public static void testSymmetricCiphers() throws Exception {
        // AES variants
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
        aesKeyGen.init(256);
        SecretKey aesKey = aesKeyGen.generateKey();
        
        // AES/CBC/PKCS5Padding
        Cipher aesCbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        aesCbc.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        
        // AES/GCM/NoPadding
        Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, new byte[12]);
        aesGcm.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
        
        // AES/ECB/PKCS5Padding
        Cipher aesEcb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesEcb.init(Cipher.ENCRYPT_MODE, aesKey);
        
        // DES
        KeyGenerator desKeyGen = KeyGenerator.getInstance("DES");
        SecretKey desKey = desKeyGen.generateKey();
        Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding");
        des.init(Cipher.ENCRYPT_MODE, desKey, new IvParameterSpec(new byte[8]));
        
        // DESede (3DES)
        KeyGenerator desedeKeyGen = KeyGenerator.getInstance("DESede");
        SecretKey desedeKey = desedeKeyGen.generateKey();
        Cipher desede = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        desede.init(Cipher.ENCRYPT_MODE, desedeKey, new IvParameterSpec(new byte[8]));
        
        // Blowfish
        KeyGenerator blowfishKeyGen = KeyGenerator.getInstance("Blowfish");
        SecretKey blowfishKey = blowfishKeyGen.generateKey();
        Cipher blowfish = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        blowfish.init(Cipher.ENCRYPT_MODE, blowfishKey, new IvParameterSpec(new byte[8]));
        
        // RC4
        KeyGenerator rc4KeyGen = KeyGenerator.getInstance("RC4");
        SecretKey rc4Key = rc4KeyGen.generateKey();
        Cipher rc4 = Cipher.getInstance("RC4");
        rc4.init(Cipher.ENCRYPT_MODE, rc4Key);
        
        // RC2
        KeyGenerator rc2KeyGen = KeyGenerator.getInstance("RC2");
        SecretKey rc2Key = rc2KeyGen.generateKey();
        Cipher rc2 = Cipher.getInstance("RC2/CBC/PKCS5Padding");
        rc2.init(Cipher.ENCRYPT_MODE, rc2Key, new IvParameterSpec(new byte[8]));
        
        // ChaCha20
        KeyGenerator chachaKeyGen = KeyGenerator.getInstance("ChaCha20");
        SecretKey chachaKey = chachaKeyGen.generateKey();
        Cipher chacha20 = Cipher.getInstance("ChaCha20");
        IvParameterSpec chachaIv = new IvParameterSpec(new byte[12]);
        chacha20.init(Cipher.ENCRYPT_MODE, chachaKey, chachaIv);
        
        // ChaCha20-Poly1305
        Cipher chacha20Poly1305 = Cipher.getInstance("ChaCha20-Poly1305");
        IvParameterSpec chachaPolyIv = new IvParameterSpec(new byte[12]);
        chacha20Poly1305.init(Cipher.ENCRYPT_MODE, chachaKey, chachaPolyIv);
    }
    
    public static void testAsymmetricAlgorithms() throws Exception {
        // RSA
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        KeyPair rsaKeyPair = rsaKpg.generateKeyPair();
        
        // RSA/ECB/PKCS1Padding
        Cipher rsaPkcs1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaPkcs1.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
        
        // RSA/ECB/OAEPPadding
        Cipher rsaOaep = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsaOaep.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
        
        // RSA with OAEP and SHA-256
        Cipher rsaOaepSha256 = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaOaepSha256.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
        
        // EC (Elliptic Curve) - NIST curves
        // P-256
        KeyPairGenerator ecKpg256 = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec256 = new ECGenParameterSpec("secp256r1");
        ecKpg256.initialize(ecSpec256);
        KeyPair ecKeyPair256 = ecKpg256.generateKeyPair();
        
        // P-384
        KeyPairGenerator ecKpg384 = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec384 = new ECGenParameterSpec("secp384r1");
        ecKpg384.initialize(ecSpec384);
        KeyPair ecKeyPair384 = ecKpg384.generateKeyPair();
        
        // P-521
        KeyPairGenerator ecKpg521 = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec521 = new ECGenParameterSpec("secp521r1");
        ecKpg521.initialize(ecSpec521);
        KeyPair ecKeyPair521 = ecKpg521.generateKeyPair();
        
        // DH (Diffie-Hellman)
        KeyPairGenerator dhKpg = KeyPairGenerator.getInstance("DH");
        dhKpg.initialize(2048);
        KeyPair dhKeyPair = dhKpg.generateKeyPair();
        
        // Key Agreement
        KeyAgreement dhKeyAgree = KeyAgreement.getInstance("DH");
        dhKeyAgree.init(dhKeyPair.getPrivate());
        
        // DSA
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA");
        dsaKpg.initialize(2048);
        KeyPair dsaKeyPair = dsaKpg.generateKeyPair();
    }
    
    public static void testSignatureAlgorithms() throws Exception {
        // Generate keys for testing
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        KeyPair rsaKeyPair = rsaKpg.generateKeyPair();
        
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA");
        dsaKpg.initialize(2048);
        KeyPair dsaKeyPair = dsaKpg.generateKeyPair();
        
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKeyPair = ecKpg.generateKeyPair();
        
        byte[] data = "Test data".getBytes();
        
        // RSA signatures
        // SHA1withRSA
        Signature sha1Rsa = Signature.getInstance("SHA1withRSA");
        sha1Rsa.initSign(rsaKeyPair.getPrivate());
        sha1Rsa.update(data);
        sha1Rsa.sign();
        
        // SHA256withRSA
        Signature sha256Rsa = Signature.getInstance("SHA256withRSA");
        sha256Rsa.initSign(rsaKeyPair.getPrivate());
        sha256Rsa.update(data);
        sha256Rsa.sign();
        
        // SHA512withRSA
        Signature sha512Rsa = Signature.getInstance("SHA512withRSA");
        sha512Rsa.initSign(rsaKeyPair.getPrivate());
        sha512Rsa.update(data);
        sha512Rsa.sign();
        
        // DSA signatures
        // SHA1withDSA
        Signature sha1Dsa = Signature.getInstance("SHA1withDSA");
        sha1Dsa.initSign(dsaKeyPair.getPrivate());
        sha1Dsa.update(data);
        sha1Dsa.sign();
        
        // SHA256withDSA
        Signature sha256Dsa = Signature.getInstance("SHA256withDSA");
        sha256Dsa.initSign(dsaKeyPair.getPrivate());
        sha256Dsa.update(data);
        sha256Dsa.sign();
        
        // ECDSA signatures
        // SHA256withECDSA
        Signature sha256Ecdsa = Signature.getInstance("SHA256withECDSA");
        sha256Ecdsa.initSign(ecKeyPair.getPrivate());
        sha256Ecdsa.update(data);
        sha256Ecdsa.sign();
        
        // SHA384withECDSA
        KeyPairGenerator ecKpg384 = KeyPairGenerator.getInstance("EC");
        ecKpg384.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair ecKeyPair384 = ecKpg384.generateKeyPair();
        
        Signature sha384Ecdsa = Signature.getInstance("SHA384withECDSA");
        sha384Ecdsa.initSign(ecKeyPair384.getPrivate());
        sha384Ecdsa.update(data);
        sha384Ecdsa.sign();
        
        // SHA512withECDSA
        KeyPairGenerator ecKpg521 = KeyPairGenerator.getInstance("EC");
        ecKpg521.initialize(new ECGenParameterSpec("secp521r1"));
        KeyPair ecKeyPair521 = ecKpg521.generateKeyPair();
        
        Signature sha512Ecdsa = Signature.getInstance("SHA512withECDSA");
        sha512Ecdsa.initSign(ecKeyPair521.getPrivate());
        sha512Ecdsa.update(data);
        sha512Ecdsa.sign();
        
        // RSASSA-PSS
        Signature rsaPss = Signature.getInstance("RSASSA-PSS");
        rsaPss.initSign(rsaKeyPair.getPrivate());
        rsaPss.update(data);
        rsaPss.sign();
        
        // Ed25519
        KeyPairGenerator ed25519Kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair ed25519KeyPair = ed25519Kpg.generateKeyPair();
        
        Signature ed25519Sig = Signature.getInstance("Ed25519");
        ed25519Sig.initSign(ed25519KeyPair.getPrivate());
        ed25519Sig.update(data);
        ed25519Sig.sign();
        
        // Ed448
        KeyPairGenerator ed448Kpg = KeyPairGenerator.getInstance("Ed448");
        KeyPair ed448KeyPair = ed448Kpg.generateKeyPair();
        
        Signature ed448Sig = Signature.getInstance("Ed448");
        ed448Sig.initSign(ed448KeyPair.getPrivate());
        ed448Sig.update(data);
        ed448Sig.sign();
    }
    
    public static void testHashAlgorithms() throws Exception {
        byte[] data = "Test data".getBytes();
        
        // MD5
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(data);
        md5.digest();
        
        // SHA-1
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        sha1.update(data);
        sha1.digest();
        
        // SHA-224
        MessageDigest sha224 = MessageDigest.getInstance("SHA-224");
        sha224.update(data);
        sha224.digest();
        
        // SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(data);
        sha256.digest();
        
        // SHA-384
        MessageDigest sha384 = MessageDigest.getInstance("SHA-384");
        sha384.update(data);
        sha384.digest();
        
        // SHA-512
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        sha512.update(data);
        sha512.digest();
        
        // SHA3-224
        MessageDigest sha3_224 = MessageDigest.getInstance("SHA3-224");
        sha3_224.update(data);
        sha3_224.digest();
        
        // SHA3-256
        MessageDigest sha3_256 = MessageDigest.getInstance("SHA3-256");
        sha3_256.update(data);
        sha3_256.digest();
        
        // SHA3-384
        MessageDigest sha3_384 = MessageDigest.getInstance("SHA3-384");
        sha3_384.update(data);
        sha3_384.digest();
        
        // SHA3-512
        MessageDigest sha3_512 = MessageDigest.getInstance("SHA3-512");
        sha3_512.update(data);
        sha3_512.digest();
    }
    
    public static void testMacAlgorithms() throws Exception {
        byte[] data = "Test data".getBytes();
        
        // HmacMD5
        KeyGenerator hmacMd5KeyGen = KeyGenerator.getInstance("HmacMD5");
        SecretKey hmacMd5Key = hmacMd5KeyGen.generateKey();
        Mac hmacMd5 = Mac.getInstance("HmacMD5");
        hmacMd5.init(hmacMd5Key);
        hmacMd5.doFinal(data);
        
        // HmacSHA1
        KeyGenerator hmacSha1KeyGen = KeyGenerator.getInstance("HmacSHA1");
        SecretKey hmacSha1Key = hmacSha1KeyGen.generateKey();
        Mac hmacSha1 = Mac.getInstance("HmacSHA1");
        hmacSha1.init(hmacSha1Key);
        hmacSha1.doFinal(data);
        
        // HmacSHA224
        KeyGenerator hmacSha224KeyGen = KeyGenerator.getInstance("HmacSHA224");
        SecretKey hmacSha224Key = hmacSha224KeyGen.generateKey();
        Mac hmacSha224 = Mac.getInstance("HmacSHA224");
        hmacSha224.init(hmacSha224Key);
        hmacSha224.doFinal(data);
        
        // HmacSHA256
        KeyGenerator hmacSha256KeyGen = KeyGenerator.getInstance("HmacSHA256");
        SecretKey hmacSha256Key = hmacSha256KeyGen.generateKey();
        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        hmacSha256.init(hmacSha256Key);
        hmacSha256.doFinal(data);
        
        // HmacSHA384
        KeyGenerator hmacSha384KeyGen = KeyGenerator.getInstance("HmacSHA384");
        SecretKey hmacSha384Key = hmacSha384KeyGen.generateKey();
        Mac hmacSha384 = Mac.getInstance("HmacSHA384");
        hmacSha384.init(hmacSha384Key);
        hmacSha384.doFinal(data);
        
        // HmacSHA512
        KeyGenerator hmacSha512KeyGen = KeyGenerator.getInstance("HmacSHA512");
        SecretKey hmacSha512Key = hmacSha512KeyGen.generateKey();
        Mac hmacSha512 = Mac.getInstance("HmacSHA512");
        hmacSha512.init(hmacSha512Key);
        hmacSha512.doFinal(data);
        
        // HmacSHA3-224
        KeyGenerator hmacSha3_224KeyGen = KeyGenerator.getInstance("HmacSHA3-224");
        SecretKey hmacSha3_224Key = hmacSha3_224KeyGen.generateKey();
        Mac hmacSha3_224 = Mac.getInstance("HmacSHA3-224");
        hmacSha3_224.init(hmacSha3_224Key);
        hmacSha3_224.doFinal(data);
        
        // HmacSHA3-256
        KeyGenerator hmacSha3_256KeyGen = KeyGenerator.getInstance("HmacSHA3-256");
        SecretKey hmacSha3_256Key = hmacSha3_256KeyGen.generateKey();
        Mac hmacSha3_256 = Mac.getInstance("HmacSHA3-256");
        hmacSha3_256.init(hmacSha3_256Key);
        hmacSha3_256.doFinal(data);
        
        // HmacSHA3-384
        KeyGenerator hmacSha3_384KeyGen = KeyGenerator.getInstance("HmacSHA3-384");
        SecretKey hmacSha3_384Key = hmacSha3_384KeyGen.generateKey();
        Mac hmacSha3_384 = Mac.getInstance("HmacSHA3-384");
        hmacSha3_384.init(hmacSha3_384Key);
        hmacSha3_384.doFinal(data);
        
        // HmacSHA3-512
        KeyGenerator hmacSha3_512KeyGen = KeyGenerator.getInstance("HmacSHA3-512");
        SecretKey hmacSha3_512Key = hmacSha3_512KeyGen.generateKey();
        Mac hmacSha3_512 = Mac.getInstance("HmacSHA3-512");
        hmacSha3_512.init(hmacSha3_512Key);
        hmacSha3_512.doFinal(data);
    }
    
    public static void testKdfAlgorithms() throws Exception {
        char[] password = "password".toCharArray();
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        
        // PBKDF2WithHmacSHA1
        SecretKeyFactory pbkdf2Sha1 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec pbeSpec1 = new PBEKeySpec(password, salt, 10000, 256);
        SecretKey pbkdf2Sha1Key = pbkdf2Sha1.generateSecret(pbeSpec1);
        
        // PBKDF2WithHmacSHA256
        SecretKeyFactory pbkdf2Sha256 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec pbeSpec256 = new PBEKeySpec(password, salt, 10000, 256);
        SecretKey pbkdf2Sha256Key = pbkdf2Sha256.generateSecret(pbeSpec256);
        
        // PBKDF2WithHmacSHA512
        SecretKeyFactory pbkdf2Sha512 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec pbeSpec512 = new PBEKeySpec(password, salt, 10000, 256);
        SecretKey pbkdf2Sha512Key = pbkdf2Sha512.generateSecret(pbeSpec512);
    }
    
    public static void main(String[] args) throws Exception {
        testSymmetricCiphers();
        testAsymmetricAlgorithms();
        testSignatureAlgorithms();
        testHashAlgorithms();
        testMacAlgorithms();
        testKdfAlgorithms();
        
        System.out.println("All tests completed");
    }
}
