use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rand::rngs::OsRng;

fn main() {
    let mut rng = OsRng;
    
    // Generate a 2048-bit RSA key pair
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    
    // Test message
    let data = b"hello world";
    
    // Encrypt
    let enc_data = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .expect("failed to encrypt");
    
    // Decrypt
    let dec_data = private_key
        .decrypt(Pkcs1v15Encrypt, &enc_data)
        .expect("failed to decrypt");
    
    assert_eq!(&data[..], &dec_data[..]);
    println!("RSA 2048-bit encryption/decryption successful!");
}