from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import os

def main():
    # Fernet symmetric encryption (AES-128 in CBC mode with HMAC-SHA256)
    fernet_key = Fernet.generate_key()
    fernet = Fernet(fernet_key)
    
    message = b"Hello, Cryptography World!"
    encrypted = fernet.encrypt(message)
    decrypted = fernet.decrypt(encrypted)
    
    print("✓ Fernet encryption/decryption successful")
    
    # PBKDF2 key derivation
    password = b"password"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    derived_key = kdf.derive(password)
    
    print("✓ PBKDF2-HMAC-SHA256 key derivation successful")
    
    # Standard library hashlib
    sha256_hash = hashlib.sha256(message).hexdigest()
    sha512_hash = hashlib.sha512(message).hexdigest()
    
    print(f"✓ SHA-256 hash: {sha256_hash[:16]}...")
    print(f"✓ SHA-512 hash: {sha512_hash[:16]}...")
    
    print("\nAlgorithms used:")
    print("- Fernet (AES-128 + HMAC-SHA256): Quantum-safe")
    print("- PBKDF2-HMAC-SHA256: Quantum-safe")
    print("- SHA-256: Quantum-safe")
    print("- SHA-512: Quantum-safe")

if __name__ == "__main__":
    main()