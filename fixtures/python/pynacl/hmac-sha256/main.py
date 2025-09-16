import nacl.hash
import nacl.utils
import hmac

# Note: PyNaCl doesn't have HMAC directly, using Python's hmac with nacl utilities
key = nacl.utils.random(32)
message = b"Hello, World!"

# Create HMAC
mac = hmac.new(key, message, nacl.hash.sha256).digest()

# Verify HMAC
expected_mac = hmac.new(key, message, nacl.hash.sha256).digest()
valid = hmac.compare_digest(mac, expected_mac)
