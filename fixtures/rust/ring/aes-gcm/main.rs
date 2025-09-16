use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

fn main() {
    let rng = SystemRandom::new();
    
    // Generate key
    let mut key_bytes = [0u8; 32];
    rng.fill(&mut key_bytes).unwrap();
    
    let unbound_key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
    let key = LessSafeKey::new(unbound_key);
    
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes).unwrap();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    
    let plaintext = b"Hello, World!";
    let mut ciphertext = plaintext.to_vec();
    
    // Encrypt
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext).unwrap();
    
    // Decrypt
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let decrypted = key.open_in_place(nonce, Aad::empty(), &mut ciphertext).unwrap();
}
