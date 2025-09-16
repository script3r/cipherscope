from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Generate key and nonce
key = get_random_bytes(32)
nonce = get_random_bytes(12)
plaintext = b"Hello, World!"

# Encrypt
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# Decrypt
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
decrypted = cipher.decrypt_and_verify(ciphertext, tag)
