import tink
from tink import signature

# Register primitives
signature.register()

# Generate key pair
private_keyset_handle = tink.new_keyset_handle(
    signature.signature_key_templates.RSA_PSS_3072_SHA256_F4)
public_keyset_handle = private_keyset_handle.public_keyset_handle()

# Get primitives
signer = private_keyset_handle.primitive(signature.PublicKeySign)
verifier = public_keyset_handle.primitive(signature.PublicKeyVerify)

message = b"Hello, World!"

# Sign
sig = signer.sign(message)

# Verify
verifier.verify(sig, message)
