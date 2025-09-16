from Crypto.Hash import HMAC, SHA256

key = b"secret_key"
message = b"Hello, World!"

# Create HMAC
h = HMAC.new(key, digestmod=SHA256)
h.update(message)
mac = h.digest()

# Verify HMAC
h = HMAC.new(key, digestmod=SHA256)
h.update(message)
h.verify(mac)  # Raises exception if invalid
