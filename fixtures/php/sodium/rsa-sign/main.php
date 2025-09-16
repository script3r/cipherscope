<?php
// Note: PHP Sodium doesn't support RSA, using Ed25519 instead
$keypair = sodium_crypto_sign_keypair();
$secret_key = sodium_crypto_sign_secretkey($keypair);
$public_key = sodium_crypto_sign_publickey($keypair);

$message = "Hello, World!";

// Sign
$signed = sodium_crypto_sign($message, $secret_key);

// Verify
$unsigned = sodium_crypto_sign_open($signed, $public_key);
?>
