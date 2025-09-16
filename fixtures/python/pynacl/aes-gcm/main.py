import nacl.secret
import nacl.utils

# Note: PyNaCl doesn't support AES-GCM, using SecretBox (XSalsa20-Poly1305) instead
key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
box = nacl.secret.SecretBox(key)

plaintext = b"Hello, World!"

# Encrypt
encrypted = box.encrypt(plaintext)

# Decrypt
decrypted = box.decrypt(encrypted)
