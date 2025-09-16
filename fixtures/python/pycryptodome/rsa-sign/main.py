from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

message = b"Hello, World!"

# Generate RSA key pair
key = RSA.generate(2048)

# Sign
h = SHA256.new(message)
signature = pss.new(key).sign(h)

# Verify
h = SHA256.new(message)
verifier = pss.new(key)
verifier.verify(h, signature)  # Raises exception if invalid
