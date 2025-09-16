use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair};

fn main() {
    let message = b"Hello, World!";
    let rng = SystemRandom::new();
    
    // Generate RSA key pair
    let key_pair = signature::RsaKeyPair::generate_pkcs8(
        &signature::RSA_PSS_2048_8192_SHA256,
        &rng
    ).unwrap();
    
    let key_pair = signature::RsaKeyPair::from_pkcs8(key_pair.as_ref()).unwrap();
    
    // Sign
    let mut signature = vec![0; key_pair.public_modulus_len()];
    key_pair.sign(&signature::RSA_PSS_SHA256, &rng, message, &mut signature).unwrap();
    
    // Verify
    let public_key = signature::UnparsedPublicKey::new(
        &signature::RSA_PSS_2048_8192_SHA256,
        key_pair.public_key().as_ref()
    );
    public_key.verify(message, &signature).unwrap();
}
