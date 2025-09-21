use ring::aead;
use ring::digest;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, KeyPair};

fn test_aead() {
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &[0u8; 32]).unwrap()
    );
    
    let nonce = aead::Nonce::assume_unique_for_key([0u8; 12]);
    let mut data = b"plaintext".to_vec();
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut data).unwrap();
}

fn test_digest() {
    let data = b"hello world";
    let digest = digest::digest(&digest::SHA256, data);
    let sha512_digest = digest::digest(&digest::SHA512, data);
    let sha1_digest = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data);
}

fn test_pbkdf2() {
    let password = b"password";
    let salt = b"salt";
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(),
        salt,
        password,
        &mut key,
    );
}

fn test_signature() {
    let rng = SystemRandom::new();
    
    // Ed25519
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
    
    // ECDSA P-256
    let ecdsa_key = signature::EcdsaKeyPair::generate_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    ).unwrap();
}

fn main() {
    test_aead();
    test_digest();
    test_pbkdf2();
    test_signature();
}
