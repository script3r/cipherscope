use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce
};

fn main() {
    // Generate key and nonce
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    let plaintext = b"Hello, World!";
    
    // Encrypt
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
    
    // Decrypt
    let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
}
