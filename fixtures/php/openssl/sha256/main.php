<?php
$message = "Hello, World!";

$hash = openssl_digest($message, 'sha256', true);
?>
