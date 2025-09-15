//! Algorithm detection functionality for extracting cryptographic algorithms from source code

use anyhow::{Context, Result};
use scanner_core::{CompiledAlgorithm, Finding, PatternRegistry};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::{AlgorithmProperties, AssetProperties, AssetType, CryptoAsset, CryptographicPrimitive};

/// Detector for cryptographic algorithms in source code
pub struct AlgorithmDetector {
    /// Reference to the pattern registry for algorithm definitions
    registry: Option<std::sync::Arc<PatternRegistry>>,
}

impl AlgorithmDetector {
    pub fn new() -> Self {
        Self { registry: None }
    }

    pub fn with_registry(registry: std::sync::Arc<PatternRegistry>) -> Self {
        Self {
            registry: Some(registry),
        }
    }

    /// Detect algorithms from scanner findings using pattern registry
    pub fn detect_algorithms(
        &self,
        scan_path: &Path,
        findings: &[Finding],
    ) -> Result<Vec<CryptoAsset>> {
        let mut algorithms = Vec::new();
        let mut seen_algorithms = HashSet::new();

        if let Some(registry) = &self.registry {
            // Extract algorithms from findings using registry patterns
            for finding in findings {
                if let Some(algorithm_assets) =
                    self.extract_algorithms_from_finding_with_registry(finding, registry)?
                {
                    for asset in algorithm_assets {
                        let key = format!(
                            "{}:{}",
                            asset.name.as_ref().unwrap_or(&"unknown".to_string()),
                            asset.bom_ref
                        );
                        if seen_algorithms.insert(key) {
                            algorithms.push(asset);
                        }
                    }
                }
            }

            // Perform additional static analysis for parameter extraction
            let additional_algorithms =
                self.perform_deep_static_analysis_with_registry(scan_path, registry)?;
            for asset in additional_algorithms {
                let key = format!(
                    "{}:{}",
                    asset.name.as_ref().unwrap_or(&"unknown".to_string()),
                    asset.bom_ref
                );
                if seen_algorithms.insert(key) {
                    algorithms.push(asset);
                }
            }
        } else {
            // Fallback to hardcoded detection if no registry available
            for finding in findings {
                if let Some(algorithm_assets) =
                    self.extract_algorithms_from_finding_fallback(finding)?
                {
                    for asset in algorithm_assets {
                        let key = format!(
                            "{}:{}",
                            asset.name.as_ref().unwrap_or(&"unknown".to_string()),
                            asset.bom_ref
                        );
                        if seen_algorithms.insert(key) {
                            algorithms.push(asset);
                        }
                    }
                }
            }
        }

        Ok(algorithms)
    }

    /// Extract algorithms from finding using pattern registry
    fn extract_algorithms_from_finding_with_registry(
        &self,
        finding: &Finding,
        registry: &PatternRegistry,
    ) -> Result<Option<Vec<CryptoAsset>>> {
        let mut algorithms = Vec::new();

        // Find the library in the registry
        if let Some(library) = registry.libs.iter().find(|lib| lib.name == finding.library) {
            // Check each algorithm defined for this library
            for algorithm in &library.algorithms {
                // Check if the finding symbol matches any of the algorithm's symbol patterns
                if self.symbol_matches_algorithm(&finding.symbol, algorithm) {
                    // Extract parameters from the finding
                    let parameters = self.extract_parameters_from_finding(finding, algorithm)?;

                    // Create the algorithm asset
                    let asset = self.create_algorithm_asset_from_spec(algorithm, parameters)?;
                    algorithms.push(asset);
                }
            }
        }

        if algorithms.is_empty() {
            Ok(None)
        } else {
            Ok(Some(algorithms))
        }
    }

    /// Fallback algorithm extraction for when no registry is available
    fn extract_algorithms_from_finding_fallback(
        &self,
        finding: &Finding,
    ) -> Result<Option<Vec<CryptoAsset>>> {
        // Simplified fallback logic
        let symbol = &finding.symbol.to_lowercase();
        let mut algorithms = Vec::new();

        if symbol.contains("rsa") {
            algorithms.push(self.create_rsa_algorithm(2048));
        } else if symbol.contains("aes") && symbol.contains("gcm") {
            algorithms.push(self.create_aes_gcm_algorithm(256));
        } else if symbol.contains("aes") {
            algorithms.push(self.create_aes_algorithm(256));
        } else if symbol.contains("sha256") {
            algorithms.push(self.create_sha_algorithm(256));
        }

        if algorithms.is_empty() {
            Ok(None)
        } else {
            Ok(Some(algorithms))
        }
    }

    /// Check if a symbol matches an algorithm's patterns
    fn symbol_matches_algorithm(&self, symbol: &str, algorithm: &CompiledAlgorithm) -> bool {
        if algorithm.symbol_patterns.is_empty() {
            // If no specific symbol patterns, assume it matches (will be refined by library detection)
            return true;
        }

        // Check if symbol matches any of the algorithm's symbol patterns
        algorithm
            .symbol_patterns
            .iter()
            .any(|pattern| pattern.is_match(symbol))
    }

    /// Extract parameters from finding using algorithm's parameter patterns
    fn extract_parameters_from_finding(
        &self,
        finding: &Finding,
        algorithm: &CompiledAlgorithm,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let mut parameters = HashMap::new();

        // Try to extract parameters from multiple sources
        let sources = vec![&finding.symbol, &finding.snippet];

        for param_pattern in &algorithm.parameter_patterns {
            let mut found_value = false;

            // Try each source (symbol, snippet) for parameter extraction
            for source in &sources {
                if let Some(captures) = param_pattern.pattern.captures(source) {
                    if let Some(value_match) = captures.get(1) {
                        let value_str = value_match.as_str();

                        // Try to parse as number first, then as string
                        let value = if let Ok(num) = value_str.parse::<u64>() {
                            json!(num)
                        } else {
                            json!(value_str)
                        };

                        parameters.insert(param_pattern.name.clone(), value);
                        found_value = true;
                        break; // Found value, no need to check other sources
                    }
                }
            }

            // Use default value if pattern doesn't match any source
            if !found_value {
                if let Some(default) = &param_pattern.default_value {
                    parameters.insert(param_pattern.name.clone(), default.clone());
                }
            }
        }

        Ok(parameters)
    }

    /// Create algorithm asset from algorithm spec and extracted parameters
    fn create_algorithm_asset_from_spec(
        &self,
        algorithm: &CompiledAlgorithm,
        parameters: HashMap<String, serde_json::Value>,
    ) -> Result<CryptoAsset> {
        let primitive = self.parse_primitive(&algorithm.primitive)?;

        let parameter_set = if parameters.is_empty() {
            None
        } else {
            Some(json!(parameters))
        };

        Ok(CryptoAsset {
            bom_ref: Uuid::new_v4().to_string(),
            asset_type: AssetType::Algorithm,
            name: Some(algorithm.name.clone()),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive,
                parameter_set,
                nist_quantum_security_level: algorithm.nist_quantum_security_level,
            }),
        })
    }

    /// Parse primitive string to enum
    fn parse_primitive(&self, primitive_str: &str) -> Result<CryptographicPrimitive> {
        match primitive_str.to_lowercase().as_str() {
            "signature" => Ok(CryptographicPrimitive::Signature),
            "pke" => Ok(CryptographicPrimitive::PublicKeyEncryption),
            "hash" => Ok(CryptographicPrimitive::Hash),
            "kem" => Ok(CryptographicPrimitive::KeyEncapsulationMechanism),
            "aead" => Ok(CryptographicPrimitive::AuthenticatedEncryption),
            "mac" => Ok(CryptographicPrimitive::MessageAuthenticationCode),
            "kdf" => Ok(CryptographicPrimitive::KeyDerivationFunction),
            "prng" => Ok(CryptographicPrimitive::PseudoRandomNumberGenerator),
            _ => Err(anyhow::anyhow!("Unknown primitive type: {}", primitive_str)),
        }
    }

    /// Perform deep static analysis using registry patterns
    fn perform_deep_static_analysis_with_registry(
        &self,
        scan_path: &Path,
        registry: &PatternRegistry,
    ) -> Result<Vec<CryptoAsset>> {
        let mut algorithms = Vec::new();

        // Walk through source files for parameter extraction
        for entry in WalkDir::new(scan_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();

            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if matches!(
                    ext,
                    "rs" | "java" | "go" | "py" | "c" | "cpp" | "swift" | "js" | "php"
                ) {
                    if let Ok(mut extracted) = self.analyze_file_with_registry(path, registry) {
                        algorithms.append(&mut extracted);
                    }
                }
            }
        }

        Ok(algorithms)
    }

    /// Analyze a source file using registry patterns
    fn analyze_file_with_registry(
        &self,
        file_path: &Path,
        registry: &PatternRegistry,
    ) -> Result<Vec<CryptoAsset>> {
        let content = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

        let mut algorithms = Vec::new();

        // Check all libraries and their algorithms
        for library in &registry.libs {
            for algorithm in &library.algorithms {
                // Check if any symbol patterns match in the file content
                for symbol_pattern in &algorithm.symbol_patterns {
                    for symbol_match in symbol_pattern.find_iter(&content) {
                        let symbol = symbol_match.as_str();

                        // Extract parameters from the matched symbol
                        let mut parameters = HashMap::new();
                        for param_pattern in &algorithm.parameter_patterns {
                            if let Some(captures) = param_pattern.pattern.captures(symbol) {
                                if let Some(value_match) = captures.get(1) {
                                    let value_str = value_match.as_str();
                                    let value = if let Ok(num) = value_str.parse::<u64>() {
                                        json!(num)
                                    } else {
                                        json!(value_str)
                                    };
                                    parameters.insert(param_pattern.name.clone(), value);
                                }
                            }
                        }

                        // Create algorithm asset
                        let asset = self.create_algorithm_asset_from_spec(algorithm, parameters)?;
                        algorithms.push(asset);
                    }
                }
            }
        }

        Ok(algorithms)
    }

    // Essential helper methods for fallback scenarios

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
}

impl Default for AlgorithmDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scanner_core::{Finding, Language, Span};
    use std::path::PathBuf;

    #[test]
    fn test_algorithm_detector_creation() {
        let detector = AlgorithmDetector::new();
        assert!(detector.registry.is_none());
    }

    #[test]
    fn test_primitive_parsing() {
        let detector = AlgorithmDetector::new();

        assert!(matches!(
            detector.parse_primitive("signature").unwrap(),
            CryptographicPrimitive::Signature
        ));
        assert!(matches!(
            detector.parse_primitive("aead").unwrap(),
            CryptographicPrimitive::AuthenticatedEncryption
        ));
        assert!(matches!(
            detector.parse_primitive("hash").unwrap(),
            CryptographicPrimitive::Hash
        ));
    }

    #[test]
    fn test_fallback_algorithm_extraction() {
        let detector = AlgorithmDetector::new();

        let finding = Finding {
            language: Language::Rust,
            library: "unknown".to_string(),
            file: PathBuf::from("src/main.rs"),
            span: Span { line: 1, column: 1 },
            symbol: "rsa::RsaPrivateKey".to_string(),
            snippet: "use rsa::RsaPrivateKey;".to_string(),
            detector_id: "detector-rust".to_string(),
        };

        let algorithms = detector
            .extract_algorithms_from_finding_fallback(&finding)
            .unwrap();
        assert!(algorithms.is_some());

        let algos = algorithms.unwrap();
        assert_eq!(algos.len(), 1);
        assert_eq!(algos[0].name, Some("RSA".to_string()));
    }
}
