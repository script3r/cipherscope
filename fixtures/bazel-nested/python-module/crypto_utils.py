from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes

def main():
    # Fernet encryption
    key = Fernet.generate_key()
    fernet = Fernet(key)
    
    message = b"Bazel Python Module: Fernet encryption"
    encrypted = fernet.encrypt(message)
    decrypted = fernet.decrypt(encrypted)
    
    print("✓ Fernet encryption/decryption successful")
    
    # SHA-256 hashing
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hash_value = digest.finalize()
    
    print(f"✓ SHA-256 hash computed: {hash_value.hex()[:16]}...")

if __name__ == "__main__":
    main()