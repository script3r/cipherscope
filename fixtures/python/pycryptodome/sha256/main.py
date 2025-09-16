from Crypto.Hash import SHA256

message = b"Hello, World!"

hash_obj = SHA256.new()
hash_obj.update(message)
digest = hash_obj.digest()
