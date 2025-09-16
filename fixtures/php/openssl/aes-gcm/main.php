<?php
$plaintext = "Hello, World!";
$key = random_bytes(32);
$iv = random_bytes(12);

// Encrypt
$ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

// Decrypt
$decrypted = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
?>
