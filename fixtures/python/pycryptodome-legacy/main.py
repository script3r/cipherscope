from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def main():
    # RSA key generation with PyCryptodome
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey()
    
    # Message to sign
    message = b"Hello, PyCryptodome World!"
    
    # SHA-256 hash
    hash_obj = SHA256.new(message)
    
    # RSA signature
    signature = pkcs1_15.new(rsa_key).sign(hash_obj)
    
    # Verify signature
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        print("✓ RSA signature verification successful")
    except ValueError:
        print("✗ RSA signature verification failed")
    
    # AES encryption
    aes_key = get_random_bytes(32)  # 256-bit key
    cipher = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    
    print("✓ AES-256-EAX encryption successful")
    print("✓ SHA-256 hash computed")
    print("✓ RSA 2048-bit signature created")
    
    print("\nPQC Status:")
    print("- RSA 2048-bit: VULNERABLE to quantum attacks")
    print("- AES-256: SAFE from quantum attacks")
    print("- SHA-256: SAFE from quantum attacks")

if __name__ == "__main__":
    main()