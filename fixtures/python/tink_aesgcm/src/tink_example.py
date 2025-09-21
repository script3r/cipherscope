import tink
from tink import aead
from tink import cleartext_keyset_handle

def main():
    # Register AEAD key types
    aead.register()
    
    # Generate a new AES-GCM key
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    
    # Get the AEAD primitive
    aead_primitive = keyset_handle.primitive(aead.Aead)
    
    # Encrypt data
    plaintext = b'Hello Tink Python'
    associated_data = b'metadata'
    ciphertext = aead_primitive.encrypt(plaintext, associated_data)
    
    # Decrypt data
    decrypted = aead_primitive.decrypt(ciphertext, associated_data)
    print(f"Decrypted: {decrypted.decode()}")
    
    # Also demonstrate AES-CTR-HMAC
    ctr_template = aead.aead_key_templates.AES256_CTR_HMAC_SHA256
    ctr_handle = tink.new_keyset_handle(ctr_template)
    ctr_aead = ctr_handle.primitive(aead.Aead)
    
    # And ChaCha20-Poly1305
    chacha_template = aead.aead_key_templates.CHACHA20_POLY1305
    chacha_handle = tink.new_keyset_handle(chacha_template)
    chacha_aead = chacha_handle.primitive(aead.Aead)

if __name__ == '__main__':
    main()
