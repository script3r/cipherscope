use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use aes_gcm::{Aes256Gcm, KeyInit, Aead, Nonce};
use sha2::{Sha256, Sha512, Digest};
use ed25519_dalek::{SigningKey, Signature, Signer, Verifier, VerifyingKey};
use ring::{digest, signature};
use rand::rngs::OsRng;

fn main() {
    println!("Testing mixed cryptographic algorithms...");
    
    // RSA 2048-bit (PQC vulnerable)
    let mut rng = OsRng;
    let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key");
    let rsa_public_key = RsaPublicKey::from(&rsa_private_key);
    println!("✓ RSA 2048-bit key pair generated");
    
    // AES-256-GCM (PQC safe)
    let aes_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
    let aes_cipher = Aes256Gcm::new(aes_key);
    let aes_nonce = Nonce::from_slice(&[0u8; 12]);
    println!("✓ AES-256-GCM cipher initialized");
    
    // SHA-256 and SHA-512 (PQC safe)
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(b"test message");
    let sha256_result = sha256_hasher.finalize();
    println!("✓ SHA-256 hash computed: {:x}", sha256_result);
    
    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(b"test message");
    let sha512_result = sha512_hasher.finalize();
    println!("✓ SHA-512 hash computed");
    
    // Ed25519 (PQC vulnerable)
    let ed25519_signing_key = SigningKey::generate(&mut rng);
    let ed25519_verifying_key = ed25519_signing_key.verifying_key();
    let ed25519_signature: Signature = ed25519_signing_key.sign(b"test message");
    println!("✓ Ed25519 signature created");
    
    // Ring digest (PQC safe)
    let ring_digest = digest::digest(&digest::SHA256, b"test message");
    println!("✓ Ring SHA-256 digest computed");
    
    // Ring ECDSA (PQC vulnerable) 
    let ring_rng = ring::rand::SystemRandom::new();
    let ring_pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&ring_rng)
        .expect("failed to generate Ed25519 key");
    println!("✓ Ring Ed25519 key generated");
    
    println!("Mixed crypto test completed!");
    println!("PQC Vulnerable: RSA-2048, Ed25519");
    println!("PQC Safe: AES-256-GCM, SHA-256, SHA-512");
    println!("Implements but unused: p256 (ECDSA P-256)");
}