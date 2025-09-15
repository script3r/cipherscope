//! Algorithm detection functionality for extracting cryptographic algorithms from source code

use anyhow::{Context, Result};
use regex::Regex;
use scanner_core::{Finding, Language};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::{
    AlgorithmProperties, AssetProperties, AssetType, CryptographicPrimitive, CryptoAsset,
};

/// Detector for cryptographic algorithms in source code
pub struct AlgorithmDetector {
    /// Regex patterns for extracting algorithm parameters
    parameter_patterns: HashMap<String, Vec<Regex>>,
}

impl AlgorithmDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            parameter_patterns: HashMap::new(),
        };
        
        detector.initialize_parameter_patterns();
        detector
    }

    /// Detect algorithms from scanner findings and additional static analysis
    pub fn detect_algorithms(&self, scan_path: &Path, findings: &[Finding]) -> Result<Vec<CryptoAsset>> {
        let mut algorithms = Vec::new();
        let mut seen_algorithms = HashSet::new();

        // Extract algorithms from existing findings
        for finding in findings {
            if let Some(algorithm_assets) = self.extract_algorithms_from_finding(finding)? {
                for asset in algorithm_assets {
                    let key = format!("{}:{}", asset.name.as_ref().unwrap_or(&"unknown".to_string()), 
                                    asset.bom_ref);
                    if seen_algorithms.insert(key) {
                        algorithms.push(asset);
                    }
                }
            }
        }

        // Perform additional static analysis for parameter extraction
        let additional_algorithms = self.perform_deep_static_analysis(scan_path)?;
        for asset in additional_algorithms {
            let key = format!("{}:{}", asset.name.as_ref().unwrap_or(&"unknown".to_string()), 
                            asset.bom_ref);
            if seen_algorithms.insert(key) {
                algorithms.push(asset);
            }
        }

        Ok(algorithms)
    }

    /// Extract algorithm information from a scanner finding
    fn extract_algorithms_from_finding(&self, finding: &Finding) -> Result<Option<Vec<CryptoAsset>>> {
        let mut algorithms = Vec::new();

        // Map library names to algorithms
        match finding.library.as_str() {
            "RustCrypto (common crates)" => {
                algorithms.extend(self.extract_rustcrypto_algorithms(finding)?);
            }
            "ring" => {
                algorithms.extend(self.extract_ring_algorithms(finding)?);
            }
            "openssl (Rust)" => {
                algorithms.extend(self.extract_openssl_algorithms(finding)?);
            }
            "OpenSSL" => {
                algorithms.extend(self.extract_openssl_c_algorithms(finding)?);
            }
            "Java JCA/JCE" => {
                algorithms.extend(self.extract_jca_algorithms(finding)?);
            }
            "Go std crypto" => {
                algorithms.extend(self.extract_go_crypto_algorithms(finding)?);
            }
            "PyCA cryptography" => {
                algorithms.extend(self.extract_pyca_algorithms(finding)?);
            }
            _ => {
                // Generic algorithm extraction based on symbol names
                if let Some(algo) = self.extract_generic_algorithm(finding)? {
                    algorithms.push(algo);
                }
            }
        }

        if algorithms.is_empty() {
            Ok(None)
        } else {
            Ok(Some(algorithms))
        }
    }

    /// Extract algorithms from RustCrypto findings
    fn extract_rustcrypto_algorithms(&self, finding: &Finding) -> Result<Vec<CryptoAsset>> {
        let mut algorithms = Vec::new();
        let symbol = &finding.symbol;

        // Map RustCrypto symbols to algorithms
        if symbol.contains("aes_gcm") || symbol.contains("Aes") {
            let key_size = self.extract_aes_key_size(symbol).unwrap_or(256);
            algorithms.push(self.create_aes_gcm_algorithm(key_size));
        } else if symbol.contains("chacha20poly1305") || symbol.contains("ChaCha20Poly1305") {
            algorithms.push(self.create_chacha20poly1305_algorithm());
        } else if symbol.contains("sha2") || symbol.contains("Sha") {
            let hash_size = self.extract_sha_size(symbol).unwrap_or(256);
            algorithms.push(self.create_sha_algorithm(hash_size));
        } else if symbol.contains("sha3") {
            algorithms.push(self.create_sha3_algorithm());
        } else if symbol.contains("blake3") {
            algorithms.push(self.create_blake3_algorithm());
        } else if symbol.contains("blake2") {
            algorithms.push(self.create_blake2_algorithm());
        } else if symbol.contains("ed25519_dalek") || symbol.contains("Ed25519") {
            algorithms.push(self.create_ed25519_algorithm());
        } else if symbol.contains("curve25519_dalek") {
            algorithms.push(self.create_x25519_algorithm());
        }

        Ok(algorithms)
    }

    /// Extract algorithms from ring findings
    fn extract_ring_algorithms(&self, finding: &Finding) -> Result<Vec<CryptoAsset>> {
        let mut algorithms = Vec::new();
        let symbol = &finding.symbol;

        // Ring contains multiple algorithms - try to identify which ones
        if symbol.contains("RSA") || symbol.contains("rsa") {
            // Default to RSA-2048 if no specific key size found
            let key_size = self.extract_rsa_key_size(symbol).unwrap_or(2048);
            algorithms.push(self.create_rsa_algorithm(key_size));
        }
        
        if symbol.contains("ECDSA") || symbol.contains("ecdsa") {
            algorithms.push(self.create_ecdsa_algorithm("P-256".to_string()));
        }
        
        if symbol.contains("AES") || symbol.contains("aes") {
            algorithms.push(self.create_aes_gcm_algorithm(256));
        }
        
        if symbol.contains("ChaCha20Poly1305") || symbol.contains("chacha20") {
            algorithms.push(self.create_chacha20poly1305_algorithm());
        }

        Ok(algorithms)
    }

    /// Extract algorithms from OpenSSL findings
    fn extract_openssl_algorithms(&self, finding: &Finding) -> Result<Vec<CryptoAsset>> {
        let mut algorithms = Vec::new();
        let symbol = &finding.symbol;

        if symbol.contains("RSA") || symbol.contains("rsa") {
            let key_size = self.extract_rsa_key_size(symbol).unwrap_or(2048);
            algorithms.push(self.create_rsa_algorithm(key_size));
        }
        
        if symbol.contains("ECDSA") || symbol.contains("ecdsa") || symbol.contains("EC_KEY") {
            algorithms.push(self.create_ecdsa_algorithm("P-256".to_string()));
        }

        Ok(algorithms)
    }

    /// Extract algorithms from OpenSSL C findings
    fn extract_openssl_c_algorithms(&self, finding: &Finding) -> Result<Vec<CryptoAsset>> {
        self.extract_openssl_algorithms(finding) // Same logic for now
    }

    /// Extract algorithms from Java JCA/JCE findings
    fn extract_jca_algorithms(&self, finding: &Finding) -> Result<Vec<CryptoAsset>> {
        let mut algorithms = Vec::new();
        let symbol = &finding.symbol;

        // JCA/JCE algorithm extraction is more complex due to getInstance patterns
        if symbol.contains("RSA") {
            algorithms.push(self.create_rsa_algorithm(2048)); // Default RSA key size
        }
        
        if symbol.contains("AES") {
            algorithms.push(self.create_aes_algorithm(256));
        }
        
        if symbol.contains("SHA") {
            algorithms.push(self.create_sha_algorithm(256));
        }

        Ok(algorithms)
    }

    /// Extract algorithms from Go crypto findings
    fn extract_go_crypto_algorithms(&self, finding: &Finding) -> Result<Vec<CryptoAsset>> {
        let mut algorithms = Vec::new();
        let symbol = &finding.symbol;

        if symbol.contains("rsa") {
            algorithms.push(self.create_rsa_algorithm(2048));
        }
        
        if symbol.contains("ecdsa") {
            algorithms.push(self.create_ecdsa_algorithm("P-256".to_string()));
        }
        
        if symbol.contains("aes") {
            algorithms.push(self.create_aes_algorithm(256));
        }
        
        if symbol.contains("sha256") {
            algorithms.push(self.create_sha_algorithm(256));
        } else if symbol.contains("sha512") {
            algorithms.push(self.create_sha_algorithm(512));
        }

        Ok(algorithms)
    }

    /// Extract algorithms from PyCA cryptography findings
    fn extract_pyca_algorithms(&self, finding: &Finding) -> Result<Vec<CryptoAsset>> {
        let mut algorithms = Vec::new();
        let symbol = &finding.symbol;

        if symbol.contains("RSA") {
            algorithms.push(self.create_rsa_algorithm(2048));
        }
        
        if symbol.contains("AESGCM") {
            algorithms.push(self.create_aes_gcm_algorithm(256));
        }
        
        if symbol.contains("ChaCha20Poly1305") {
            algorithms.push(self.create_chacha20poly1305_algorithm());
        }

        Ok(algorithms)
    }

    /// Generic algorithm extraction for unknown libraries
    fn extract_generic_algorithm(&self, finding: &Finding) -> Result<Option<CryptoAsset>> {
        let symbol = &finding.symbol.to_lowercase();

        if symbol.contains("rsa") {
            Ok(Some(self.create_rsa_algorithm(2048)))
        } else if symbol.contains("ecdsa") || symbol.contains("ecc") {
            Ok(Some(self.create_ecdsa_algorithm("P-256".to_string())))
        } else if symbol.contains("aes") {
            Ok(Some(self.create_aes_algorithm(256)))
        } else if symbol.contains("sha256") {
            Ok(Some(self.create_sha_algorithm(256)))
        } else {
            Ok(None)
        }
    }

    /// Perform deep static analysis on source files
    fn perform_deep_static_analysis(&self, scan_path: &Path) -> Result<Vec<CryptoAsset>> {
        let mut algorithms = Vec::new();

        // Walk through Rust source files for parameter extraction
        for entry in WalkDir::new(scan_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext == "rs" {
                    if let Ok(mut extracted) = self.analyze_rust_file(path) {
                        algorithms.append(&mut extracted);
                    }
                }
            }
        }

        Ok(algorithms)
    }

    /// Analyze a Rust source file for algorithm parameters
    fn analyze_rust_file(&self, file_path: &Path) -> Result<Vec<CryptoAsset>> {
        let content = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

        let mut algorithms = Vec::new();

        // Look for RSA key generation with explicit key sizes
        if let Some(rsa_patterns) = self.parameter_patterns.get("rsa") {
            for pattern in rsa_patterns {
                for capture in pattern.captures_iter(&content) {
                    if let Some(key_size_match) = capture.get(1) {
                        if let Ok(key_size) = key_size_match.as_str().parse::<u32>() {
                            algorithms.push(self.create_rsa_algorithm(key_size));
                        }
                    }
                }
            }
        }

        // Look for AES key sizes
        if let Some(aes_patterns) = self.parameter_patterns.get("aes") {
            for pattern in aes_patterns {
                for capture in pattern.captures_iter(&content) {
                    if let Some(key_size_match) = capture.get(1) {
                        if let Ok(key_size) = key_size_match.as_str().parse::<u32>() {
                            algorithms.push(self.create_aes_algorithm(key_size));
                        }
                    }
                }
            }
        }

        Ok(algorithms)
    }

    /// Initialize regex patterns for parameter extraction
    fn initialize_parameter_patterns(&mut self) {
        // RSA key size patterns
        let rsa_patterns = vec![
            Regex::new(r"RSA.*?(\d{4})").unwrap(), // RSA with 4-digit key size
            Regex::new(r"generate_key\s*\(\s*(\d+)").unwrap(), // generate_key(2048)
            Regex::new(r"RsaKeyPair::generate\s*\(\s*(\d+)").unwrap(), // Ring RSA generation
        ];
        self.parameter_patterns.insert("rsa".to_string(), rsa_patterns);

        // AES key size patterns
        let aes_patterns = vec![
            Regex::new(r"Aes(\d+)").unwrap(), // Aes128, Aes256, etc.
            Regex::new(r"AES.*?(\d+)").unwrap(), // AES with key size
        ];
        self.parameter_patterns.insert("aes".to_string(), aes_patterns);
    }

    // Helper methods to create specific algorithm assets

    fn create_rsa_algorithm(&self, key_size: u32) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some("RSA".to_string()),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::Signature,
                parameter_set: Some(json!({"keySize": key_size})),
                nist_quantum_security_level: 0, // Vulnerable to quantum attacks
            }),
        }
    }

    fn create_ecdsa_algorithm(&self, curve: String) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some("ECDSA".to_string()),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::Signature,
                parameter_set: Some(json!({"curve": curve})),
                nist_quantum_security_level: 0, // Vulnerable to quantum attacks
            }),
        }
    }

    fn create_aes_algorithm(&self, key_size: u32) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some(format!("AES-{}", key_size)),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::AuthenticatedEncryption,
                parameter_set: Some(json!({"keySize": key_size})),
                nist_quantum_security_level: if key_size >= 256 { 3 } else { 1 },
            }),
        }
    }

    fn create_aes_gcm_algorithm(&self, key_size: u32) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some(format!("AES-{}-GCM", key_size)),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::AuthenticatedEncryption,
                parameter_set: Some(json!({"keySize": key_size, "mode": "GCM"})),
                nist_quantum_security_level: if key_size >= 256 { 3 } else { 1 },
            }),
        }
    }

    fn create_chacha20poly1305_algorithm(&self) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some("ChaCha20Poly1305".to_string()),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::AuthenticatedEncryption,
                parameter_set: Some(json!({"keySize": 256})),
                nist_quantum_security_level: 3, // Quantum-safe
            }),
        }
    }

    fn create_sha_algorithm(&self, hash_size: u32) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some(format!("SHA-{}", hash_size)),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::Hash,
                parameter_set: Some(json!({"outputSize": hash_size})),
                nist_quantum_security_level: if hash_size >= 384 { 3 } else { 1 },
            }),
        }
    }

    fn create_sha3_algorithm(&self) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some("SHA-3".to_string()),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::Hash,
                parameter_set: Some(json!({"family": "SHA-3"})),
                nist_quantum_security_level: 3, // Quantum-safe
            }),
        }
    }

    fn create_blake3_algorithm(&self) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some("BLAKE3".to_string()),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::Hash,
                parameter_set: Some(json!({"outputSize": 256})),
                nist_quantum_security_level: 3, // Quantum-safe
            }),
        }
    }

    fn create_blake2_algorithm(&self) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some("BLAKE2".to_string()),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::Hash,
                parameter_set: Some(json!({"family": "BLAKE2"})),
                nist_quantum_security_level: 3, // Quantum-safe
            }),
        }
    }

    fn create_ed25519_algorithm(&self) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some("Ed25519".to_string()),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::Signature,
                parameter_set: Some(json!({"curve": "Curve25519"})),
                nist_quantum_security_level: 0, // Vulnerable to quantum attacks
            }),
        }
    }

    fn create_x25519_algorithm(&self) -> CryptoAsset {
        CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some("X25519".to_string()),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive: CryptographicPrimitive::KeyEncapsulationMechanism,
                parameter_set: Some(json!({"curve": "Curve25519"})),
                nist_quantum_security_level: 0, // Vulnerable to quantum attacks
            }),
        }
    }

    // Helper methods for parameter extraction

    fn extract_aes_key_size(&self, symbol: &str) -> Option<u32> {
        if symbol.contains("128") {
            Some(128)
        } else if symbol.contains("192") {
            Some(192)
        } else if symbol.contains("256") {
            Some(256)
        } else {
            None
        }
    }

    fn extract_sha_size(&self, symbol: &str) -> Option<u32> {
        if symbol.contains("224") {
            Some(224)
        } else if symbol.contains("256") {
            Some(256)
        } else if symbol.contains("384") {
            Some(384)
        } else if symbol.contains("512") {
            Some(512)
        } else {
            None
        }
    }

    fn extract_rsa_key_size(&self, symbol: &str) -> Option<u32> {
        // Look for common RSA key sizes
        if symbol.contains("1024") {
            Some(1024)
        } else if symbol.contains("2048") {
            Some(2048)
        } else if symbol.contains("3072") {
            Some(3072)
        } else if symbol.contains("4096") {
            Some(4096)
        } else {
            None
        }
    }
}

impl Default for AlgorithmDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scanner_core::{Finding, Span};
    use std::path::PathBuf;

    #[test]
    fn test_algorithm_detector_creation() {
        let detector = AlgorithmDetector::new();
        assert!(!detector.parameter_patterns.is_empty());
    }

    #[test]
    fn test_rustcrypto_algorithm_extraction() {
        let detector = AlgorithmDetector::new();
        
        let finding = Finding {
            language: Language::Rust,
            library: "RustCrypto (common crates)".to_string(),
            file: PathBuf::from("src/main.rs"),
            span: Span { line: 1, column: 1 },
            symbol: "aes_gcm::Aes256Gcm".to_string(),
            snippet: "use aes_gcm::Aes256Gcm;".to_string(),
            detector_id: "detector-rust".to_string(),
        };

        let algorithms = detector.extract_rustcrypto_algorithms(&finding).unwrap();
        assert!(!algorithms.is_empty());
        
        let aes_algo = &algorithms[0];
        assert_eq!(aes_algo.name, Some("AES-256-GCM".to_string()));
        assert!(matches!(aes_algo.asset_type, AssetType::Algorithm));
    }

    #[test]
    fn test_rsa_key_size_extraction() {
        let detector = AlgorithmDetector::new();
        
        assert_eq!(detector.extract_rsa_key_size("RSA2048"), Some(2048));
        assert_eq!(detector.extract_rsa_key_size("rsa_4096_key"), Some(4096));
        assert_eq!(detector.extract_rsa_key_size("some_other_function"), None);
    }

    #[test]
    fn test_quantum_security_levels() {
        let detector = AlgorithmDetector::new();
        
        let rsa_algo = detector.create_rsa_algorithm(2048);
        if let AssetProperties::Algorithm(props) = &rsa_algo.asset_properties {
            assert_eq!(props.nist_quantum_security_level, 0); // Vulnerable
        }
        
        let aes_algo = detector.create_aes_algorithm(256);
        if let AssetProperties::Algorithm(props) = &aes_algo.asset_properties {
            assert_eq!(props.nist_quantum_security_level, 3); // Quantum-safe
        }
    }
}