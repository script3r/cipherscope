<?php
$key = "secret_key";
$message = "Hello, World!";

// Create HMAC
$mac = hash_hmac('sha256', $message, $key, true);

// Verify HMAC
$expectedMac = hash_hmac('sha256', $message, $key, true);
$valid = hash_equals($mac, $expectedMac);
?>
