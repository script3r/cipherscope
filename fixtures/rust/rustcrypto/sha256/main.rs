use sha2::{Sha256, Digest};

fn main() {
    let message = b"Hello, World!";
    
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
}
