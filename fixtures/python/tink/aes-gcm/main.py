import tink
from tink import aead

# Register primitives
aead.register()

# Generate key
keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM)

# Get primitive
aead_primitive = keyset_handle.primitive(aead.Aead)

plaintext = b"Hello, World!"
associated_data = b""

# Encrypt
ciphertext = aead_primitive.encrypt(plaintext, associated_data)

# Decrypt
decrypted = aead_primitive.decrypt(ciphertext, associated_data)
