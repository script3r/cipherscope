#!/usr/bin/env python3
"""Comprehensive test of PyCA cryptography algorithms."""

import os
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa, dsa, ec, ed25519, ed448, x25519, x448, dh, padding, utils
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import (
    ChaCha20Poly1305, AESGCM, AESOCB3, AESCCM, AESGCMSIV
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.kdf.kbkdf import (
    KBKDFHMAC, KBKDFCMAC, Mode, CounterLocation
)
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash, ConcatKDFHMAC
from cryptography.hazmat.backends import default_backend

def test_symmetric_ciphers():
    """Test symmetric cipher algorithms."""
    backend = default_backend()
    key = os.urandom(32)
    iv = os.urandom(16)
    nonce = os.urandom(12)
    data = b"Test data for encryption"
    
    # AES modes
    # AES-CBC
    cipher_cbc = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=backend
    )
    encryptor_cbc = cipher_cbc.encryptor()
    
    # AES-CTR
    cipher_ctr = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=backend
    )
    encryptor_ctr = cipher_ctr.encryptor()
    
    # AES-ECB
    cipher_ecb = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=backend
    )
    encryptor_ecb = cipher_ecb.encryptor()
    
    # AES-GCM (using AESGCM class)
    aesgcm = AESGCM(key)
    ciphertext_gcm = aesgcm.encrypt(nonce, data, None)
    
    # AES-OCB3
    aesocb3 = AESOCB3(key)
    ciphertext_ocb3 = aesocb3.encrypt(nonce, data, None)
    
    # AES-OFB
    cipher_ofb = Cipher(
        algorithms.AES(key),
        modes.OFB(iv),
        backend=backend
    )
    encryptor_ofb = cipher_ofb.encryptor()
    
    # AES-CFB
    cipher_cfb = Cipher(
        algorithms.AES(key),
        modes.CFB(iv),
        backend=backend
    )
    encryptor_cfb = cipher_cfb.encryptor()
    
    # AES-CCM
    aesccm = AESCCM(key)
    ciphertext_ccm = aesccm.encrypt(nonce[:13], data, None)
    
    # AES-GCM-SIV
    aesgcmsiv = AESGCMSIV(key)
    ciphertext_gcmsiv = aesgcmsiv.encrypt(nonce, data, None)
    
    # ChaCha20
    cipher_chacha = Cipher(
        algorithms.ChaCha20(key, nonce[:16]),
        mode=None,
        backend=backend
    )
    encryptor_chacha = cipher_chacha.encryptor()
    
    # ChaCha20Poly1305
    chacha_poly = ChaCha20Poly1305(key)
    ciphertext_chacha_poly = chacha_poly.encrypt(nonce, data, None)
    
    # TripleDES (3DES)
    key_3des = os.urandom(24)
    iv_3des = os.urandom(8)
    cipher_3des = Cipher(
        algorithms.TripleDES(key_3des),
        modes.CBC(iv_3des),
        backend=backend
    )
    encryptor_3des = cipher_3des.encryptor()
    
    # Camellia
    cipher_camellia = Cipher(
        algorithms.Camellia(key),
        modes.CBC(iv),
        backend=backend
    )
    encryptor_camellia = cipher_camellia.encryptor()
    
    # CAST5
    key_cast5 = os.urandom(16)
    cipher_cast5 = Cipher(
        algorithms.CAST5(key_cast5),
        modes.CBC(iv_3des),
        backend=backend
    )
    encryptor_cast5 = cipher_cast5.encryptor()
    
    # IDEA
    key_idea = os.urandom(16)
    cipher_idea = Cipher(
        algorithms.IDEA(key_idea),
        modes.CBC(iv_3des),
        backend=backend
    )
    encryptor_idea = cipher_idea.encryptor()
    
    # SEED
    key_seed = os.urandom(16)
    cipher_seed = Cipher(
        algorithms.SEED(key_seed),
        modes.CBC(iv),
        backend=backend
    )
    encryptor_seed = cipher_seed.encryptor()
    
    # SM4
    key_sm4 = os.urandom(16)
    cipher_sm4 = Cipher(
        algorithms.SM4(key_sm4),
        modes.CBC(iv),
        backend=backend
    )
    encryptor_sm4 = cipher_sm4.encryptor()

def test_asymmetric_algorithms():
    """Test asymmetric cryptography algorithms."""
    # RSA
    private_key_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key_rsa = private_key_rsa.public_key()
    
    # RSA encryption with PKCS1v15
    ciphertext_pkcs1 = public_key_rsa.encrypt(
        b"Test message",
        padding.PKCS1v15()
    )
    
    # RSA encryption with OAEP
    ciphertext_oaep = public_key_rsa.encrypt(
        b"Test message",
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # ECC - NIST curves
    # P-256
    private_key_p256 = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    
    # P-384
    private_key_p384 = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    
    # P-521
    private_key_p521 = ec.generate_private_key(
        ec.SECP521R1(), default_backend()
    )
    
    # secp256k1
    private_key_secp256k1 = ec.generate_private_key(
        ec.SECP256K1(), default_backend()
    )
    
    # Ed25519
    private_key_ed25519 = ed25519.Ed25519PrivateKey.generate()
    public_key_ed25519 = private_key_ed25519.public_key()
    
    # Ed448
    private_key_ed448 = ed448.Ed448PrivateKey.generate()
    public_key_ed448 = private_key_ed448.public_key()
    
    # X25519
    private_key_x25519 = x25519.X25519PrivateKey.generate()
    public_key_x25519 = private_key_x25519.public_key()
    
    # X448
    private_key_x448 = x448.X448PrivateKey.generate()
    public_key_x448 = private_key_x448.public_key()
    
    # DSA
    private_key_dsa = dsa.generate_private_key(
        key_size=2048,
        backend=default_backend()
    )
    
    # DH (Diffie-Hellman)
    parameters_dh = dh.generate_parameters(
        generator=2,
        key_size=2048,
        backend=default_backend()
    )
    private_key_dh = parameters_dh.generate_private_key()
    public_key_dh = private_key_dh.public_key()

def test_signature_algorithms():
    """Test digital signature algorithms."""
    message = b"Message to sign"
    
    # RSA signatures
    private_key_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # RSA with SHA-1
    signature_rsa_sha1 = private_key_rsa.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    
    # RSA with SHA-224
    signature_rsa_sha224 = private_key_rsa.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA224()
    )
    
    # RSA with SHA-256
    signature_rsa_sha256 = private_key_rsa.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # RSA with SHA-384
    signature_rsa_sha384 = private_key_rsa.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA384()
    )
    
    # RSA with SHA-512
    signature_rsa_sha512 = private_key_rsa.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA512()
    )
    
    # RSA-PSS signatures
    signature_rsa_pss = private_key_rsa.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # ECDSA signatures
    private_key_ec = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    
    # ECDSA with SHA-1
    signature_ecdsa_sha1 = private_key_ec.sign(
        message,
        ec.ECDSA(hashes.SHA1())
    )
    
    # ECDSA with SHA-224
    signature_ecdsa_sha224 = private_key_ec.sign(
        message,
        ec.ECDSA(hashes.SHA224())
    )
    
    # ECDSA with SHA-256
    signature_ecdsa_sha256 = private_key_ec.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    
    # ECDSA with SHA-384
    private_key_ec384 = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    signature_ecdsa_sha384 = private_key_ec384.sign(
        message,
        ec.ECDSA(hashes.SHA384())
    )
    
    # ECDSA with SHA-512
    private_key_ec521 = ec.generate_private_key(
        ec.SECP521R1(), default_backend()
    )
    signature_ecdsa_sha512 = private_key_ec521.sign(
        message,
        ec.ECDSA(hashes.SHA512())
    )
    
    # Ed25519
    private_key_ed25519 = ed25519.Ed25519PrivateKey.generate()
    signature_ed25519 = private_key_ed25519.sign(message)
    
    # Ed448
    private_key_ed448 = ed448.Ed448PrivateKey.generate()
    signature_ed448 = private_key_ed448.sign(message)
    
    # DSA signatures
    private_key_dsa = dsa.generate_private_key(
        key_size=2048,
        backend=default_backend()
    )
    
    # DSA with SHA-1
    signature_dsa_sha1 = private_key_dsa.sign(
        message,
        hashes.SHA1()
    )
    
    # DSA with SHA-224
    signature_dsa_sha224 = private_key_dsa.sign(
        message,
        hashes.SHA224()
    )
    
    # DSA with SHA-256
    signature_dsa_sha256 = private_key_dsa.sign(
        message,
        hashes.SHA256()
    )

def test_hash_algorithms():
    """Test cryptographic hash algorithms."""
    data = b"Data to hash"
    
    # SHA-1
    digest_sha1 = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest_sha1.update(data)
    hash_sha1 = digest_sha1.finalize()
    
    # SHA-224
    digest_sha224 = hashes.Hash(hashes.SHA224(), backend=default_backend())
    digest_sha224.update(data)
    hash_sha224 = digest_sha224.finalize()
    
    # SHA-256
    digest_sha256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest_sha256.update(data)
    hash_sha256 = digest_sha256.finalize()
    
    # SHA-384
    digest_sha384 = hashes.Hash(hashes.SHA384(), backend=default_backend())
    digest_sha384.update(data)
    hash_sha384 = digest_sha384.finalize()
    
    # SHA-512
    digest_sha512 = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest_sha512.update(data)
    hash_sha512 = digest_sha512.finalize()
    
    # SHA3-224
    digest_sha3_224 = hashes.Hash(hashes.SHA3_224(), backend=default_backend())
    digest_sha3_224.update(data)
    hash_sha3_224 = digest_sha3_224.finalize()
    
    # SHA3-256
    digest_sha3_256 = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
    digest_sha3_256.update(data)
    hash_sha3_256 = digest_sha3_256.finalize()
    
    # SHA3-384
    digest_sha3_384 = hashes.Hash(hashes.SHA3_384(), backend=default_backend())
    digest_sha3_384.update(data)
    hash_sha3_384 = digest_sha3_384.finalize()
    
    # SHA3-512
    digest_sha3_512 = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest_sha3_512.update(data)
    hash_sha3_512 = digest_sha3_512.finalize()
    
    # BLAKE2b
    digest_blake2b = hashes.Hash(hashes.BLAKE2b(64), backend=default_backend())
    digest_blake2b.update(data)
    hash_blake2b = digest_blake2b.finalize()
    
    # BLAKE2s
    digest_blake2s = hashes.Hash(hashes.BLAKE2s(32), backend=default_backend())
    digest_blake2s.update(data)
    hash_blake2s = digest_blake2s.finalize()
    
    # MD5
    digest_md5 = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest_md5.update(data)
    hash_md5 = digest_md5.finalize()
    
    # SM3
    digest_sm3 = hashes.Hash(hashes.SM3(), backend=default_backend())
    digest_sm3.update(data)
    hash_sm3 = digest_sm3.finalize()

def test_mac_algorithms():
    """Test message authentication code algorithms."""
    key = os.urandom(32)
    message = b"Message to authenticate"
    
    # HMAC with SHA-1
    h_sha1 = hmac.HMAC(key, hashes.SHA1(), backend=default_backend())
    h_sha1.update(message)
    mac_sha1 = h_sha1.finalize()
    
    # HMAC with SHA-224
    h_sha224 = hmac.HMAC(key, hashes.SHA224(), backend=default_backend())
    h_sha224.update(message)
    mac_sha224 = h_sha224.finalize()
    
    # HMAC with SHA-256
    h_sha256 = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h_sha256.update(message)
    mac_sha256 = h_sha256.finalize()
    
    # HMAC with SHA-384
    h_sha384 = hmac.HMAC(key, hashes.SHA384(), backend=default_backend())
    h_sha384.update(message)
    mac_sha384 = h_sha384.finalize()
    
    # HMAC with SHA-512
    h_sha512 = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
    h_sha512.update(message)
    mac_sha512 = h_sha512.finalize()
    
    # HMAC with SHA3-224
    h_sha3_224 = hmac.HMAC(key, hashes.SHA3_224(), backend=default_backend())
    h_sha3_224.update(message)
    mac_sha3_224 = h_sha3_224.finalize()
    
    # HMAC with SHA3-256
    h_sha3_256 = hmac.HMAC(key, hashes.SHA3_256(), backend=default_backend())
    h_sha3_256.update(message)
    mac_sha3_256 = h_sha3_256.finalize()
    
    # HMAC with SHA3-384
    h_sha3_384 = hmac.HMAC(key, hashes.SHA3_384(), backend=default_backend())
    h_sha3_384.update(message)
    mac_sha3_384 = h_sha3_384.finalize()
    
    # HMAC with SHA3-512
    h_sha3_512 = hmac.HMAC(key, hashes.SHA3_512(), backend=default_backend())
    h_sha3_512.update(message)
    mac_sha3_512 = h_sha3_512.finalize()
    
    # HMAC with BLAKE2b
    h_blake2b = hmac.HMAC(key, hashes.BLAKE2b(64), backend=default_backend())
    h_blake2b.update(message)
    mac_blake2b = h_blake2b.finalize()
    
    # HMAC with BLAKE2s
    h_blake2s = hmac.HMAC(key[:32], hashes.BLAKE2s(32), backend=default_backend())
    h_blake2s.update(message)
    mac_blake2s = h_blake2s.finalize()

def test_kdf_algorithms():
    """Test key derivation function algorithms."""
    password = b"password"
    salt = os.urandom(16)
    
    # PBKDF2HMAC
    kdf_pbkdf2 = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key_pbkdf2 = kdf_pbkdf2.derive(password)
    
    # Scrypt
    kdf_scrypt = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key_scrypt = kdf_scrypt.derive(password)
    
    # HKDF
    kdf_hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'hkdf-example',
        backend=default_backend()
    )
    key_hkdf = kdf_hkdf.derive(password)
    
    # HKDF-Expand
    kdf_hkdf_expand = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b'hkdf-expand-example',
        backend=default_backend()
    )
    key_hkdf_expand = kdf_hkdf_expand.derive(password[:32])
    
    # Note: HKDF-Extract is not directly exposed but is part of HKDF
    
    # Note: Argon2 is not directly supported by cryptography library
    # You would need to use argon2-cffi or similar
    
    # KBKDF
    kdf_kbkdf = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=None,
        location=CounterLocation.BeforeFixed,
        label=b"KBKDF",
        context=b"context",
        fixed=None,
        backend=default_backend()
    )
    key_kbkdf = kdf_kbkdf.derive(password[:32])
    
    # X963KDF
    kdf_x963 = X963KDF(
        algorithm=hashes.SHA256(),
        length=32,
        sharedinfo=b"shared",
        backend=default_backend()
    )
    key_x963 = kdf_x963.derive(password[:32])
    
    # ConcatKDF with Hash
    kdf_concat_hash = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=b"other",
        backend=default_backend()
    )
    key_concat_hash = kdf_concat_hash.derive(password[:32])
    
    # ConcatKDF with HMAC
    kdf_concat_hmac = ConcatKDFHMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        otherinfo=b"other",
        backend=default_backend()
    )
    key_concat_hmac = kdf_concat_hmac.derive(password[:32])

if __name__ == "__main__":
    test_symmetric_ciphers()
    test_asymmetric_algorithms()
    test_signature_algorithms()
    test_hash_algorithms()
    test_mac_algorithms()
    test_kdf_algorithms()
    print("All cryptography tests completed")
