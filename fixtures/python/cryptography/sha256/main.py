from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

message = b"Hello, World!"

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(message)
hash_value = digest.finalize()
