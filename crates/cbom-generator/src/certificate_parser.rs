//! Certificate parsing functionality for extracting cryptographic assets from X.509 certificates

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use walkdir::WalkDir;
use x509_parser::prelude::*;

use crate::{
    AlgorithmProperties, AssetProperties, AssetType, CertificateProperties, CryptoAsset,
    CryptographicPrimitive,
};

/// Parser for X.509 certificates and related cryptographic material
pub struct CertificateParser;

impl CertificateParser {
    pub fn new() -> Self {
        Self
    }

    /// Parse all certificates found in the given directory
    pub fn parse_certificates(&self, scan_path: &Path) -> Result<Vec<CryptoAsset>> {
        let mut certificates = Vec::new();

        // Define certificate file extensions to look for
        let cert_extensions = [
            "pem", "crt", "cer", "der", "p7b", "p7c", "pfx", "p12",
            "key", // Private key files that might contain certificates
        ];

        // Walk through the directory looking for certificate files
        for entry in WalkDir::new(scan_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();

            // Check if the file has a certificate extension
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if cert_extensions.contains(&ext.to_lowercase().as_str()) {
                    if let Ok(mut parsed_certs) = self.parse_certificate_file(path) {
                        certificates.append(&mut parsed_certs);
                    }
                }
            }
        }

        Ok(certificates)
    }

    /// Parse a single certificate file
    fn parse_certificate_file(&self, file_path: &Path) -> Result<Vec<CryptoAsset>> {
        let file_contents = fs::read(file_path)
            .with_context(|| format!("Failed to read certificate file: {}", file_path.display()))?;

        let mut certificates = Vec::new();

        // Try to parse as PEM first (most common format)
        if let Ok(pem_certs) = self.parse_pem_certificates(&file_contents) {
            certificates.extend(pem_certs);
        } else {
            // Try to parse as DER
            if let Ok(der_cert) = self.parse_der_certificate(&file_contents) {
                certificates.push(der_cert);
            }
        }

        Ok(certificates)
    }

    /// Parse PEM-encoded certificates
    fn parse_pem_certificates(&self, data: &[u8]) -> Result<Vec<CryptoAsset>> {
        let mut certificates = Vec::new();

        // Convert to string for PEM parsing
        let pem_str = String::from_utf8_lossy(data);

        // Look for PEM certificate blocks
        let mut current_pos = 0;
        while let Some(start) = pem_str[current_pos..].find("-----BEGIN CERTIFICATE-----") {
            let absolute_start = current_pos + start;
            if let Some(end) = pem_str[absolute_start..].find("-----END CERTIFICATE-----") {
                let absolute_end = absolute_start + end + "-----END CERTIFICATE-----".len();
                let pem_block = &pem_str[absolute_start..absolute_end];

                // Extract the base64 content
                if let Ok(der_data) = self.pem_to_der(pem_block) {
                    if let Ok(cert) = self.parse_der_certificate(&der_data) {
                        certificates.push(cert);
                    }
                }

                current_pos = absolute_end;
            } else {
                break;
            }
        }

        if certificates.is_empty() {
            anyhow::bail!("No valid PEM certificates found");
        }

        Ok(certificates)
    }

    /// Convert PEM block to DER bytes
    fn pem_to_der(&self, pem_block: &str) -> Result<Vec<u8>> {
        let lines: Vec<&str> = pem_block.lines().collect();
        if lines.len() < 3 {
            anyhow::bail!("Invalid PEM block");
        }

        // Skip the BEGIN and END lines
        let base64_content = lines[1..lines.len() - 1].join("");

        base64::decode(&base64_content).context("Failed to decode base64 content")
    }

    /// Parse DER-encoded certificate
    fn parse_der_certificate(&self, der_data: &[u8]) -> Result<CryptoAsset> {
        let (_, cert) =
            X509Certificate::from_der(der_data).context("Failed to parse DER certificate")?;

        // Extract certificate properties
        let subject_name = cert.subject().to_string();
        let issuer_name = cert.issuer().to_string();
        let not_valid_after = self.asn1_time_to_chrono(&cert.validity().not_after)?;

        // Extract signature algorithm
        let _signature_algorithm = cert.signature_algorithm.algorithm.to_id_string();
        let signature_algorithm_ref = Uuid::new_v4().to_string();

        // Create the certificate asset
        let cert_asset = CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Certificate,
            name: Some(self.extract_common_name(&subject_name)),
            asset_properties: AssetProperties::Certificate(CertificateProperties {
                subject_name,
                issuer_name,
                not_valid_after,
                signature_algorithm_ref: signature_algorithm_ref.clone(),
            }),
        };

        Ok(cert_asset)
    }

    /// Create an algorithm asset for a certificate's signature algorithm
    pub fn create_signature_algorithm_asset(
        &self,
        signature_algorithm_oid: &str,
        bom_ref: String,
    ) -> CryptoAsset {
        let (name, primitive, nist_level, parameter_set) =
            self.map_signature_algorithm(signature_algorithm_oid);

        CryptoAsset {
            bom_ref,
            asset_type: AssetType::Algorithm,
            name: Some(name),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive,
                parameter_set,
                nist_quantum_security_level: nist_level,
            }),
        }
    }

    /// Map signature algorithm OID to algorithm properties
    fn map_signature_algorithm(
        &self,
        oid: &str,
    ) -> (
        String,
        CryptographicPrimitive,
        u8,
        Option<serde_json::Value>,
    ) {
        match oid {
            // RSA signature algorithms - all vulnerable to quantum attacks
            "1.2.840.113549.1.1.1" => (
                "RSA".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.2.840.113549.1.1.4" => (
                "RSA with MD5".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.2.840.113549.1.1.5" => (
                "RSA with SHA-1".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.2.840.113549.1.1.11" => (
                "RSA with SHA-256".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.2.840.113549.1.1.12" => (
                "RSA with SHA-384".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.2.840.113549.1.1.13" => (
                "RSA with SHA-512".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),

            // ECDSA signature algorithms - all vulnerable to quantum attacks
            "1.2.840.10045.4.1" => (
                "ECDSA with SHA-1".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.2.840.10045.4.3.1" => (
                "ECDSA with SHA-224".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.2.840.10045.4.3.2" => (
                "ECDSA with SHA-256".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.2.840.10045.4.3.3" => (
                "ECDSA with SHA-384".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.2.840.10045.4.3.4" => (
                "ECDSA with SHA-512".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),

            // EdDSA - also vulnerable to quantum attacks
            "1.3.101.112" => (
                "Ed25519".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.3.101.113" => (
                "Ed448".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),

            // DSA - vulnerable to quantum attacks
            "1.2.840.10040.4.1" => (
                "DSA".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
            "1.2.840.10040.4.3" => (
                "DSA with SHA-1".to_string(),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),

            // Default case for unknown algorithms
            _ => (
                format!("Unknown Algorithm (OID: {})", oid),
                CryptographicPrimitive::Signature,
                0,
                None,
            ),
        }
    }

    /// Convert ASN.1 time to Chrono DateTime
    fn asn1_time_to_chrono(&self, asn1_time: &ASN1Time) -> Result<DateTime<Utc>> {
        // Convert ASN1Time to Unix timestamp
        let timestamp = asn1_time.timestamp();

        DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid timestamp: {}", timestamp))
    }

    /// Extract Common Name from a distinguished name string
    fn extract_common_name(&self, dn: &str) -> String {
        // Look for CN= in the distinguished name
        for component in dn.split(',') {
            let component = component.trim();
            if component.to_uppercase().starts_with("CN=") {
                return component[3..].to_string();
            }
        }

        // Fallback to the full DN if no CN found
        dn.to_string()
    }
}

impl Default for CertificateParser {
    fn default() -> Self {
        Self::new()
    }
}

// Add base64 decoding functionality
mod base64 {
    use anyhow::Result;

    pub fn decode(input: &str) -> Result<Vec<u8>> {
        // Simple base64 decoder - in a real implementation, you'd use the base64 crate
        // For now, we'll use a basic implementation
        use std::collections::HashMap;

        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut decode_table = HashMap::new();

        for (i, c) in alphabet.chars().enumerate() {
            decode_table.insert(c, i as u8);
        }

        let input = input.replace([' ', '\n', '\r', '\t'], "");
        let mut result = Vec::new();
        let mut buffer = 0u32;
        let mut bits_collected = 0;

        for c in input.chars() {
            if c == '=' {
                break; // Padding
            }

            if let Some(&value) = decode_table.get(&c) {
                buffer = (buffer << 6) | (value as u32);
                bits_collected += 6;

                if bits_collected >= 8 {
                    bits_collected -= 8;
                    result.push(((buffer >> bits_collected) & 0xFF) as u8);
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_parser_creation() {
        let parser = CertificateParser::new();
        // Just test that we can create the parser
        assert_eq!(std::mem::size_of_val(&parser), 0); // Zero-sized struct
    }

    #[test]
    fn test_signature_algorithm_mapping() {
        let parser = CertificateParser::new();

        // Test RSA mapping
        let (name, primitive, level, _) = parser.map_signature_algorithm("1.2.840.113549.1.1.11");
        assert_eq!(name, "RSA with SHA-256");
        assert!(matches!(primitive, CryptographicPrimitive::Signature));
        assert_eq!(level, 0); // Vulnerable to quantum attacks

        // Test ECDSA mapping
        let (name, primitive, level, _) = parser.map_signature_algorithm("1.2.840.10045.4.3.2");
        assert_eq!(name, "ECDSA with SHA-256");
        assert!(matches!(primitive, CryptographicPrimitive::Signature));
        assert_eq!(level, 0); // Vulnerable to quantum attacks
    }

    #[test]
    fn test_common_name_extraction() {
        let parser = CertificateParser::new();

        let dn = "CN=example.com,O=Example Corp,C=US";
        assert_eq!(parser.extract_common_name(dn), "example.com");

        let dn_no_cn = "O=Example Corp,C=US";
        assert_eq!(parser.extract_common_name(dn_no_cn), "O=Example Corp,C=US");
    }
}
