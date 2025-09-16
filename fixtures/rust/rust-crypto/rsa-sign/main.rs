use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Sign};
use rsa::signature::{Signer, Verifier};
use sha2::Sha256;

fn main() {
    let mut rng = rand::thread_rng();
    
    // Generate key pair
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    
    let message = b"Hello, World!";
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
    
    // Sign
    let signature = signing_key.sign(message);
    
    // Verify
    verifying_key.verify(message, &signature).unwrap();
}
