<?php
$message = "Hello, World!";

// SHA-256 hash
$hash = sodium_crypto_generichash($message, '', 32);
?>
