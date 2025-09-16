use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Sign};
use rsa::signature::{Signer, Verifier};
use sha2::Sha256;

fn main() {
    let mut rng = rand::thread_rng();
    let message = b"Hello, World!";
    
    // Generate RSA key pair
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    
    // Create signing key
    let signing_key = rsa::pss::SigningKey::<Sha256>::new(private_key);
    let verifying_key = signing_key.verifying_key();
    
    // Sign
    let signature = signing_key.sign(message);
    
    // Verify
    verifying_key.verify(message, &signature).unwrap();
}
