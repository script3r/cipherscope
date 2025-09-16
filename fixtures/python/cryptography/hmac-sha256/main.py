from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

key = b"secret_key"
message = b"Hello, World!"

# Create HMAC
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(message)
mac = h.finalize()

# Verify HMAC
h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
h.update(message)
h.verify(mac)  # Raises exception if invalid
