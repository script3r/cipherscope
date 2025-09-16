<?php
// Note: PHP Sodium doesn't support AES-GCM, using ChaCha20-Poly1305 instead
$key = sodium_crypto_aead_chacha20poly1305_keygen();
$nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
$plaintext = "Hello, World!";

// Encrypt
$ciphertext = sodium_crypto_aead_chacha20poly1305_encrypt(
    $plaintext, '', $nonce, $key
);

// Decrypt
$decrypted = sodium_crypto_aead_chacha20poly1305_decrypt(
    $ciphertext, '', $nonce, $key
);
?>
