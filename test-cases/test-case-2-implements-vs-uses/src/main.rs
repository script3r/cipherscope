use sha2::{Sha256, Digest};

fn main() {
    // Only use SHA256 - this will be "uses"
    let mut hasher = Sha256::new();
    hasher.update(b"hello world");
    let result = hasher.finalize();
    
    println!("SHA256 hash: {:x}", result);
    
    // Note: p256 crate is in Cargo.toml but never used here
    // This should create an "implements" relationship for ECDSA/P-256
}