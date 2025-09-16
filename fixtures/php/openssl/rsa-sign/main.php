<?php
$message = "Hello, World!";

// Generate RSA key pair
$config = array(
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
);
$keyPair = openssl_pkey_new($config);
openssl_pkey_export($keyPair, $privateKey);
$publicKey = openssl_pkey_get_details($keyPair)['key'];

// Sign
openssl_sign($message, $signature, $privateKey, OPENSSL_ALGO_SHA256);

// Verify
$valid = openssl_verify($message, $signature, $publicKey, OPENSSL_ALGO_SHA256);
?>
