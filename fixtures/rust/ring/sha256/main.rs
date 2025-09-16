use ring::digest;

fn main() {
    let message = b"Hello, World!";
    
    let digest = digest::digest(&digest::SHA256, message);
    let _hash = digest.as_ref();
}
