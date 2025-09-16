use ring::hmac;

fn main() {
    let key = b"secret_key";
    let message = b"Hello, World!";
    
    // Create HMAC
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, message);
    
    // Verify HMAC
    hmac::verify(&key, message, tag.as_ref()).unwrap();
}
