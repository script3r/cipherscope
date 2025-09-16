import nacl.hash

message = b"Hello, World!"

# SHA-256 hash
digest = nacl.hash.sha256(message)
