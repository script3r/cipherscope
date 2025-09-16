import tink
from tink import mac

# Register primitives
mac.register()

# Generate key
keyset_handle = tink.new_keyset_handle(mac.mac_key_templates.HMAC_SHA256_256BITTAG)

# Get primitive
mac_primitive = keyset_handle.primitive(mac.Mac)

message = b"Hello, World!"

# Create MAC
tag = mac_primitive.compute_mac(message)

# Verify MAC
mac_primitive.verify_mac(tag, message)
