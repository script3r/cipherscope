use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn main() {
    let key = b"secret_key";
    let message = b"Hello, World!";
    
    // Create HMAC
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(message);
    let result = mac.finalize();
    let code = result.into_bytes();
    
    // Verify HMAC
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(message);
    mac.verify_slice(&code).unwrap();
}
