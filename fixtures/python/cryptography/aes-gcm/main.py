from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate key and nonce
key = os.urandom(32)
nonce = os.urandom(12)
plaintext = b"Hello, World!"

# Encrypt
cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
tag = encryptor.tag

# Decrypt
decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
decrypted = decryptor.update(ciphertext) + decryptor.finalize()
