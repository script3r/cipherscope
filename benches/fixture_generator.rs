//! Synthetic fixture generator for benchmarks.
//!
//! This module provides utilities for generating synthetic test fixtures
//! with configurable file counts, sizes, and crypto pattern densities.
//! It enables comprehensive benchmarking across a range of realistic scenarios.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// Templates for generating synthetic crypto code in various languages.
/// Each template contains realistic crypto API calls that will be detected by cipherscope.
pub struct CodeTemplates;

impl CodeTemplates {
    /// Python code template with cryptography library usage
    pub fn python_crypto(size_hint: usize) -> String {
        let base = r#"from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt data using AES-GCM."""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_data(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt data using AES-GCM."""
    iv = ciphertext[:12]
    tag = ciphertext[12:28]
    ct = ciphertext[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def generate_rsa_keypair(key_size: int = 2048):
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def hash_data(data: bytes) -> bytes:
    """Hash data using SHA-256."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def derive_key(password: bytes, salt: bytes, iterations: int = 100000) -> bytes:
    """Derive a key using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

"#;
        Self::expand_to_size(base, size_hint, "python")
    }

    /// C code template with OpenSSL usage
    pub fn c_openssl(size_hint: usize) -> String {
        let base = r#"#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>

int aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return -1;

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        return -1;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *tag, const unsigned char *key,
                    const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return -1;

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag))
        return -1;

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    }
    return -1;
}

void sha256_hash(const unsigned char *data, size_t len, unsigned char *hash) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(hash, &ctx);
}

RSA *generate_rsa_keypair(int bits) {
    BIGNUM *bn = BN_new();
    RSA *rsa = RSA_new();

    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, bits, bn, NULL);

    BN_free(bn);
    return rsa;
}

"#;
        Self::expand_to_size(base, size_hint, "c")
    }

    /// Java code template with JCA usage
    pub fn java_jca(size_hint: usize) -> String {
        let base = r#"import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;

public class CryptoOperations {
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    public byte[] encryptAesGcm(byte[] plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    public byte[] decryptAesGcm(byte[] ciphertext, SecretKey key) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(ciphertext, 0, iv, 0, iv.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        return cipher.doFinal(ciphertext, iv.length, ciphertext.length - iv.length);
    }

    public SecretKey generateAesKey(int keySize) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    public KeyPair generateRsaKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    public byte[] signRsa(byte[] data, java.security.PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public byte[] hashSha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
}

"#;
        Self::expand_to_size(base, size_hint, "java")
    }

    /// Go code template with crypto usage
    pub fn go_crypto(size_hint: usize) -> String {
        let base = r#"package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"io"
)

func encryptAESGCM(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func generateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func generateECDSAKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func hashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func hashSHA512(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}

func main() {
	key := make([]byte, 32)
	rand.Read(key)

	plaintext := []byte("Hello, World!")
	ciphertext, _ := encryptAESGCM(plaintext, key)
	decrypted, _ := decryptAESGCM(ciphertext, key)

	_ = decrypted
	_ = hashSHA256(plaintext)
}

"#;
        Self::expand_to_size(base, size_hint, "go")
    }

    /// Rust code template with ring/RustCrypto usage
    pub fn rust_crypto(size_hint: usize) -> String {
        let base = r#"use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM};
use ring::digest::{digest, SHA256, SHA512};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

struct CounterNonceSequence(u64);

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&self.0.to_be_bytes());
        self.0 += 1;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

fn encrypt_aes_gcm(plaintext: &[u8], key_bytes: &[u8]) -> Vec<u8> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key_bytes).unwrap();
    let nonce_sequence = CounterNonceSequence(1);
    let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

    let mut in_out = plaintext.to_vec();
    in_out.extend_from_slice(&[0u8; 16]); // space for tag

    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .unwrap();

    in_out
}

fn hash_sha256(data: &[u8]) -> Vec<u8> {
    digest(&SHA256, data).as_ref().to_vec()
}

fn hash_sha512(data: &[u8]) -> Vec<u8> {
    digest(&SHA512, data).as_ref().to_vec()
}

fn generate_random_bytes(len: usize) -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes).unwrap();
    bytes
}

fn main() {
    let key = generate_random_bytes(32);
    let plaintext = b"Hello, World!";

    let ciphertext = encrypt_aes_gcm(plaintext, &key);
    let hash = hash_sha256(plaintext);

    println!("Encrypted {} bytes, hash {} bytes", ciphertext.len(), hash.len());
}

"#;
        Self::expand_to_size(base, size_hint, "rust")
    }

    /// Expand template to approximately the target size by adding comments and padding
    fn expand_to_size(base: &str, target_size: usize, lang: &str) -> String {
        let base_size = base.len();
        if base_size >= target_size {
            return base.to_string();
        }

        let mut result = base.to_string();

        // Add padding as comments to reach target size
        let comment_prefix = match lang {
            "python" => "#",
            "c" | "java" | "go" | "rust" => "//",
            _ => "//",
        };

        // Add realistic-looking comments to pad the file
        let padding_lines = [
            " This function handles the core encryption logic for the application.",
            " Security note: Always use authenticated encryption modes like GCM.",
            " The key size should be at least 256 bits for AES encryption.",
            " TODO: Add support for additional cipher modes in future versions.",
            " Performance optimization: Consider using hardware acceleration.",
            " Reference: NIST SP 800-38D for GCM mode specifications.",
            " Warning: Never reuse nonces with the same key in GCM mode.",
            " The initialization vector must be unique for each encryption.",
            " Error handling should be improved for production use.",
            " Consider implementing key rotation for long-running applications.",
        ];

        let mut padding_idx = 0;
        while result.len() < target_size {
            let line = format!(
                "\n{}{}\n",
                comment_prefix,
                padding_lines[padding_idx % padding_lines.len()]
            );
            result.push_str(&line);
            padding_idx += 1;

            // Prevent infinite loop
            if padding_idx > 10000 {
                break;
            }
        }

        result
    }
}

/// Configuration for generating a synthetic fixture directory
#[derive(Clone, Debug)]
pub struct FixtureConfig {
    /// Number of files to generate
    pub file_count: usize,
    /// Target size for each file in bytes (approximate)
    pub file_size: usize,
    /// Percentage of files that should contain crypto patterns (0-100)
    pub crypto_density: u8,
    /// Languages to generate (if empty, uses all)
    pub languages: Vec<String>,
}

impl Default for FixtureConfig {
    fn default() -> Self {
        Self {
            file_count: 100,
            file_size: 4096,
            crypto_density: 50,
            languages: vec![
                "python".to_string(),
                "c".to_string(),
                "java".to_string(),
                "go".to_string(),
                "rust".to_string(),
            ],
        }
    }
}

/// Generate a synthetic fixture directory for benchmarking
pub fn generate_fixture(base_path: &Path, config: &FixtureConfig) -> std::io::Result<PathBuf> {
    let fixture_path = base_path.join(format!(
        "synthetic_{}files_{}kb",
        config.file_count,
        config.file_size / 1024
    ));

    // Clean up existing directory if it exists
    if fixture_path.exists() {
        fs::remove_dir_all(&fixture_path)?;
    }
    fs::create_dir_all(&fixture_path)?;

    let langs: Vec<&str> = if config.languages.is_empty() {
        vec!["python", "c", "java", "go", "rust"]
    } else {
        config.languages.iter().map(|s| s.as_str()).collect()
    };

    let extensions: std::collections::HashMap<&str, &str> = [
        ("python", "py"),
        ("c", "c"),
        ("java", "java"),
        ("go", "go"),
        ("rust", "rs"),
    ]
    .into_iter()
    .collect();

    for i in 0..config.file_count {
        let lang = langs[i % langs.len()];
        let ext = extensions.get(lang).unwrap_or(&"txt");
        let file_name = format!("file_{:06}.{}", i, ext);
        let file_path = fixture_path.join(&file_name);

        // Determine if this file should have crypto patterns
        let has_crypto = (i as u8 * 100 / config.file_count as u8) < config.crypto_density;

        let content = if has_crypto {
            match lang {
                "python" => CodeTemplates::python_crypto(config.file_size),
                "c" => CodeTemplates::c_openssl(config.file_size),
                "java" => CodeTemplates::java_jca(config.file_size),
                "go" => CodeTemplates::go_crypto(config.file_size),
                "rust" => CodeTemplates::rust_crypto(config.file_size),
                _ => generate_empty_file(lang, config.file_size),
            }
        } else {
            generate_empty_file(lang, config.file_size)
        };

        let file = File::create(&file_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(content.as_bytes())?;
    }

    Ok(fixture_path)
}

/// Generate a file without crypto patterns (for density testing)
fn generate_empty_file(lang: &str, size: usize) -> String {
    let comment_prefix = match lang {
        "python" => "#",
        "c" | "java" | "go" | "rust" => "//",
        _ => "//",
    };

    let header = match lang {
        "python" => "# Non-crypto utility module\n\ndef process_data(data):\n    return data\n\n",
        "c" => "#include <stdio.h>\n#include <stdlib.h>\n\nint main() {\n    return 0;\n}\n\n",
        "java" => {
            "public class Utility {\n    public static void main(String[] args) {\n    }\n}\n\n"
        }
        "go" => "package main\n\nfunc main() {\n}\n\n",
        "rust" => "fn main() {\n    println!(\"Hello\");\n}\n\n",
        _ => "",
    };

    let mut result = header.to_string();
    let padding_line = format!("{} Padding line for size target\n", comment_prefix);

    while result.len() < size {
        result.push_str(&padding_line);
    }

    result
}

/// Clean up a generated fixture directory
#[allow(dead_code)]
pub fn cleanup_fixture(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

/// Generate fixtures of various sizes for benchmarking
#[allow(dead_code)]
pub fn generate_size_variants(
    base_path: &Path,
    sizes_kb: &[usize],
) -> std::io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for &size_kb in sizes_kb {
        let config = FixtureConfig {
            file_count: 10, // Small number of files, varying sizes
            file_size: size_kb * 1024,
            crypto_density: 100,                   // All files have crypto
            languages: vec!["python".to_string()], // Single language for consistency
        };
        let path = generate_fixture(base_path, &config)?;
        paths.push(path);
    }

    Ok(paths)
}

/// Generate fixtures with varying file counts
#[allow(dead_code)]
pub fn generate_scale_variants(
    base_path: &Path,
    counts: &[usize],
) -> std::io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for &count in counts {
        let config = FixtureConfig {
            file_count: count,
            file_size: 4096,    // 4KB files
            crypto_density: 50, // 50% have crypto patterns
            ..Default::default()
        };
        let path = generate_fixture(base_path, &config)?;
        paths.push(path);
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::{CodeTemplates, FixtureConfig, cleanup_fixture, generate_fixture};
    #[allow(unused_imports)]
    use tempfile::TempDir;

    #[test]
    fn test_code_templates_size() {
        let py = CodeTemplates::python_crypto(10000);
        assert!(
            py.len() >= 10000,
            "Python template should reach target size"
        );

        let c = CodeTemplates::c_openssl(10000);
        assert!(c.len() >= 10000, "C template should reach target size");
    }

    #[test]
    fn test_fixture_generation() {
        let temp_dir = TempDir::new().unwrap();
        let config = FixtureConfig {
            file_count: 5,
            file_size: 1024,
            crypto_density: 100,
            languages: vec!["python".to_string()],
        };

        let path = generate_fixture(temp_dir.path(), &config).unwrap();
        assert!(path.exists());

        let files: Vec<_> = std::fs::read_dir(&path).unwrap().collect();
        assert_eq!(files.len(), 5);

        cleanup_fixture(&path).unwrap();
        assert!(!path.exists());
    }
}
