<?php
$key = sodium_crypto_auth_keygen();
$message = "Hello, World!";

// Create authentication tag (similar to HMAC)
$mac = sodium_crypto_auth($message, $key);

// Verify authentication tag
$valid = sodium_crypto_auth_verify($mac, $message, $key);
?>
