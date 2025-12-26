<?php
// Idiomatic PHP OpenSSL AES-GCM encryption example
$plaintext = "hello";
$key = random_bytes(32); // 256-bit key
$iv = random_bytes(12);  // 96-bit IV for GCM
$tag = '';
$ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
echo strlen($ciphertext);

const AES_GCM_CIPHER = 'aes-128-gcm';
$ciphertext2 = openssl_encrypt($plaintext, AES_GCM_CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag);
echo strlen($ciphertext2);
