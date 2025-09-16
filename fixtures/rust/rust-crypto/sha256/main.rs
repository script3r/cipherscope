use sha2::{Sha256, Digest};

fn main() {
    let mut hasher = Sha256::new();
    hasher.update(b"Hello, World!");
    let result = hasher.finalize();
}
