import nacl.signing

# Note: PyNaCl doesn't support RSA, using Ed25519 instead
signing_key = nacl.signing.SigningKey.generate()
verify_key = signing_key.verify_key

message = b"Hello, World!"

# Sign
signed = signing_key.sign(message)

# Verify
verify_key.verify(signed.message, signed.signature)
