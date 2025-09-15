# Certificate Fixtures

This directory contains X.509 certificates for testing CBOM certificate parsing:

- `rsa-cert.pem`: RSA 2048-bit self-signed certificate (PQC vulnerable)
- `ecdsa-cert.pem`: ECDSA P-256 self-signed certificate (PQC vulnerable)

Expected CBOM output:
- 2 certificate assets with subject/issuer/validity information
- 2 algorithm assets for the signature algorithms (RSA, ECDSA)
- Dependencies linking certificates to their signature algorithms