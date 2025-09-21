from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = urandom(12)
ct = aesgcm.encrypt(nonce, b'hello', None)
print(len(ct))
