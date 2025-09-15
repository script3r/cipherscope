//! Dependency analysis for determining uses vs implements relationships

use anyhow::Result;
use scanner_core::Finding;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::{
    ComponentInfo, CryptoAsset, Dependency, DependencyType, AssetType,
    cargo_parser::CargoDependency,
};

/// Analyzer for determining dependency relationships between components and crypto assets
pub struct DependencyAnalyzer {
    /// Component bom-ref for the main project
    main_component_ref: String,
}

impl DependencyAnalyzer {
    pub fn new() -> Self {
        Self {
            main_component_ref: Uuid::new_v4().to_string(),
        }
    }

    /// Analyze dependencies and create the dependency graph
    pub fn analyze_dependencies(
        &self,
        _component_info: &ComponentInfo,
        algorithms: &[CryptoAsset],
        certificates: &[CryptoAsset],
        cargo_dependencies: &[CargoDependency],
        findings: &[Finding],
    ) -> Result<Vec<Dependency>> {
        let mut dependencies = Vec::new();

        // Create sets for efficient lookup
        let _algorithm_refs: HashSet<String> = algorithms.iter()
            .map(|a| a.bom_ref.clone())
            .collect();
        
        let certificate_refs: HashSet<String> = certificates.iter()
            .map(|c| c.bom_ref.clone())
            .collect();

        // Map findings to crypto assets to determine "uses" relationships
        let used_assets = self.map_findings_to_assets(findings, algorithms)?;

        // Determine "implements" relationships from Cargo dependencies
        let implemented_assets = self.map_cargo_deps_to_assets(cargo_dependencies, algorithms)?;

        // Create dependencies for "uses" relationships
        if !used_assets.is_empty() {
            dependencies.push(Dependency {
                ref_: self.main_component_ref.clone(),
                depends_on: used_assets.clone(),
                dependency_type: DependencyType::Uses,
            });
        }

        // Create dependencies for "implements" relationships (excluding those already in "uses")
        let implements_only: Vec<String> = implemented_assets.into_iter()
            .filter(|asset_ref| !used_assets.contains(asset_ref))
            .collect();

        if !implements_only.is_empty() {
            dependencies.push(Dependency {
                ref_: self.main_component_ref.clone(),
                depends_on: implements_only,
                dependency_type: DependencyType::Implements,
            });
        }

        // Create dependencies for certificates (always "uses" since they're parsed files)
        if !certificate_refs.is_empty() {
            dependencies.push(Dependency {
                ref_: self.main_component_ref.clone(),
                depends_on: certificate_refs.into_iter().collect(),
                dependency_type: DependencyType::Uses,
            });
        }

        // Create dependencies from certificates to their signature algorithms
        for certificate in certificates {
            if let Some(cert_deps) = self.create_certificate_dependencies(certificate, algorithms)? {
                dependencies.extend(cert_deps);
            }
        }

        Ok(dependencies)
    }

    /// Map scanner findings to crypto asset references
    fn map_findings_to_assets(&self, findings: &[Finding], algorithms: &[CryptoAsset]) -> Result<Vec<String>> {
        let mut used_assets = Vec::new();
        let mut seen_assets = HashSet::new();

        // Create a mapping from algorithm names to bom-refs
        let algo_name_to_ref: HashMap<String, String> = algorithms.iter()
            .filter_map(|asset| {
                asset.name.as_ref().map(|name| (name.clone(), asset.bom_ref.clone()))
            })
            .collect();

        for finding in findings {
            // Try to match findings to specific algorithms
            let potential_algorithms = self.extract_algorithms_from_finding(finding);
            
            for algo_name in potential_algorithms {
                if let Some(bom_ref) = algo_name_to_ref.get(&algo_name) {
                    if seen_assets.insert(bom_ref.clone()) {
                        used_assets.push(bom_ref.clone());
                    }
                }
            }
        }

        Ok(used_assets)
    }

    /// Map Cargo dependencies to crypto asset references
    fn map_cargo_deps_to_assets(&self, cargo_deps: &[CargoDependency], algorithms: &[CryptoAsset]) -> Result<Vec<String>> {
        let mut implemented_assets = Vec::new();
        let mut seen_assets = HashSet::new();

        // Create a mapping from crate names to potential algorithms
        let crate_to_algorithms = self.build_crate_algorithm_mapping();

        for cargo_dep in cargo_deps {
            if cargo_dep.is_crypto_related {
                if let Some(algo_names) = crate_to_algorithms.get(&cargo_dep.name) {
                    for algo_name in algo_names {
                        // Find the corresponding asset
                        if let Some(asset) = algorithms.iter().find(|a| {
                            a.name.as_ref().map_or(false, |n| n.contains(algo_name))
                        }) {
                            if seen_assets.insert(asset.bom_ref.clone()) {
                                implemented_assets.push(asset.bom_ref.clone());
                            }
                        }
                    }
                }
            }
        }

        Ok(implemented_assets)
    }

    /// Create dependencies from certificates to their signature algorithms
    fn create_certificate_dependencies(&self, certificate: &CryptoAsset, algorithms: &[CryptoAsset]) -> Result<Option<Vec<Dependency>>> {
        if let AssetType::Certificate = certificate.asset_type {
            // Extract the signature algorithm reference from certificate properties
            if let crate::AssetProperties::Certificate(cert_props) = &certificate.asset_properties {
                // Find the corresponding algorithm asset
                if let Some(sig_algo) = algorithms.iter().find(|a| a.bom_ref == cert_props.signature_algorithm_ref) {
                    return Ok(Some(vec![Dependency {
                        ref_: certificate.bom_ref.clone(),
                        depends_on: vec![sig_algo.bom_ref.clone()],
                        dependency_type: DependencyType::Uses,
                    }]));
                }
            }
        }
        Ok(None)
    }

    /// Extract algorithm names from a scanner finding
    fn extract_algorithms_from_finding(&self, finding: &Finding) -> Vec<String> {
        let mut algorithms = Vec::new();
        let symbol = &finding.symbol.to_lowercase();
        let library = &finding.library;

        // Library-specific algorithm extraction
        match library.as_str() {
            "RustCrypto (common crates)" => {
                if symbol.contains("aes") {
                    if symbol.contains("gcm") {
                        algorithms.push("AES-256-GCM".to_string());
                    } else {
                        algorithms.push("AES-256".to_string());
                    }
                }
                if symbol.contains("chacha20poly1305") {
                    algorithms.push("ChaCha20Poly1305".to_string());
                }
                if symbol.contains("sha2") || symbol.contains("sha256") {
                    algorithms.push("SHA-256".to_string());
                }
                if symbol.contains("sha512") {
                    algorithms.push("SHA-512".to_string());
                }
                if symbol.contains("sha3") {
                    algorithms.push("SHA-3".to_string());
                }
                if symbol.contains("blake3") {
                    algorithms.push("BLAKE3".to_string());
                }
                if symbol.contains("blake2") {
                    algorithms.push("BLAKE2".to_string());
                }
                if symbol.contains("ed25519") {
                    algorithms.push("Ed25519".to_string());
                }
            }
            "ring" => {
                if symbol.contains("rsa") {
                    algorithms.push("RSA".to_string());
                }
                if symbol.contains("ecdsa") {
                    algorithms.push("ECDSA".to_string());
                }
                if symbol.contains("aes") {
                    algorithms.push("AES-256-GCM".to_string());
                }
                if symbol.contains("chacha20") {
                    algorithms.push("ChaCha20Poly1305".to_string());
                }
            }
            "openssl (Rust)" | "OpenSSL" => {
                if symbol.contains("rsa") {
                    algorithms.push("RSA".to_string());
                }
                if symbol.contains("ecdsa") || symbol.contains("ec_key") {
                    algorithms.push("ECDSA".to_string());
                }
                if symbol.contains("aes") {
                    algorithms.push("AES-256".to_string());
                }
            }
            "Java JCA/JCE" => {
                if symbol.contains("rsa") {
                    algorithms.push("RSA".to_string());
                }
                if symbol.contains("aes") {
                    algorithms.push("AES-256".to_string());
                }
                if symbol.contains("sha") {
                    algorithms.push("SHA-256".to_string());
                }
            }
            _ => {
                // Generic extraction
                if symbol.contains("rsa") {
                    algorithms.push("RSA".to_string());
                }
                if symbol.contains("ecdsa") {
                    algorithms.push("ECDSA".to_string());
                }
                if symbol.contains("aes") {
                    algorithms.push("AES-256".to_string());
                }
                if symbol.contains("sha256") {
                    algorithms.push("SHA-256".to_string());
                }
            }
        }

        algorithms
    }

    /// Build a mapping from crate names to the algorithms they potentially implement
    fn build_crate_algorithm_mapping(&self) -> HashMap<String, Vec<String>> {
        let mut mapping = HashMap::new();

        // RSA crates
        mapping.insert("rsa".to_string(), vec!["RSA".to_string()]);

        // ECC crates
        mapping.insert("p256".to_string(), vec!["ECDSA".to_string(), "ECDH".to_string()]);
        mapping.insert("p384".to_string(), vec!["ECDSA".to_string(), "ECDH".to_string()]);
        mapping.insert("k256".to_string(), vec!["ECDSA".to_string()]);

        // Ed25519/Curve25519
        mapping.insert("ed25519-dalek".to_string(), vec!["Ed25519".to_string()]);
        mapping.insert("curve25519-dalek".to_string(), vec!["X25519".to_string(), "Ed25519".to_string()]);

        // Symmetric crypto
        mapping.insert("aes".to_string(), vec!["AES-128".to_string(), "AES-192".to_string(), "AES-256".to_string()]);
        mapping.insert("aes-gcm".to_string(), vec!["AES-128-GCM".to_string(), "AES-192-GCM".to_string(), "AES-256-GCM".to_string()]);
        mapping.insert("chacha20".to_string(), vec!["ChaCha20".to_string()]);
        mapping.insert("chacha20poly1305".to_string(), vec!["ChaCha20Poly1305".to_string()]);

        // Hash functions
        mapping.insert("sha2".to_string(), vec!["SHA-256".to_string(), "SHA-384".to_string(), "SHA-512".to_string()]);
        mapping.insert("sha3".to_string(), vec!["SHA-3".to_string()]);
        mapping.insert("blake2".to_string(), vec!["BLAKE2".to_string()]);
        mapping.insert("blake3".to_string(), vec!["BLAKE3".to_string()]);

        // High-level libraries
        mapping.insert("ring".to_string(), vec![
            "RSA".to_string(),
            "ECDSA".to_string(),
            "AES-256-GCM".to_string(),
            "ChaCha20Poly1305".to_string(),
            "SHA-256".to_string(),
            "SHA-384".to_string(),
            "SHA-512".to_string(),
        ]);

        mapping.insert("openssl".to_string(), vec![
            "RSA".to_string(),
            "ECDSA".to_string(),
            "AES-256".to_string(),
            "SHA-256".to_string(),
            "SHA-384".to_string(),
            "SHA-512".to_string(),
        ]);

        // Password hashing
        mapping.insert("argon2".to_string(), vec!["Argon2".to_string()]);
        mapping.insert("scrypt".to_string(), vec!["scrypt".to_string()]);
        mapping.insert("bcrypt".to_string(), vec!["bcrypt".to_string()]);

        mapping
    }

    /// Get the main component bom-ref
    pub fn get_main_component_ref(&self) -> &str {
        &self.main_component_ref
    }
}

impl Default for DependencyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlgorithmProperties, AssetProperties, CryptographicPrimitive};
    use scanner_core::{Finding, Language, Span};
    use std::path::PathBuf;

    #[test]
    fn test_dependency_analyzer_creation() {
        let analyzer = DependencyAnalyzer::new();
        assert!(!analyzer.main_component_ref.is_empty());
    }

    #[test]
    fn test_algorithm_extraction_from_finding() {
        let analyzer = DependencyAnalyzer::new();
        
        let finding = Finding {
            language: Language::Rust,
            library: "RustCrypto (common crates)".to_string(),
            file: PathBuf::from("src/main.rs"),
            span: Span { line: 1, column: 1 },
            symbol: "aes_gcm::Aes256Gcm".to_string(),
            snippet: "use aes_gcm::Aes256Gcm;".to_string(),
            detector_id: "detector-rust".to_string(),
        };

        let algorithms = analyzer.extract_algorithms_from_finding(&finding);
        assert!(algorithms.contains(&"AES-256-GCM".to_string()));
    }

    #[test]
    fn test_crate_algorithm_mapping() {
        let analyzer = DependencyAnalyzer::new();
        let mapping = analyzer.build_crate_algorithm_mapping();
        
        assert!(mapping.contains_key("rsa"));
        assert!(mapping.get("rsa").unwrap().contains(&"RSA".to_string()));
        
        assert!(mapping.contains_key("aes-gcm"));
        assert!(mapping.get("aes-gcm").unwrap().contains(&"AES-256-GCM".to_string()));
    }

    #[test]
    fn test_dependency_type_distinction() {
        let analyzer = DependencyAnalyzer::new();
        
        // Create a mock finding that would indicate "uses"
        let finding = Finding {
            language: Language::Rust,
            library: "RustCrypto (common crates)".to_string(),
            file: PathBuf::from("src/main.rs"),
            span: Span { line: 1, column: 1 },
            symbol: "aes_gcm::Aes256Gcm::new".to_string(),
            snippet: "let cipher = Aes256Gcm::new(&key);".to_string(),
            detector_id: "detector-rust".to_string(),
        };

        // Create a mock cargo dependency that would indicate "implements"
        let cargo_dep = CargoDependency {
            name: "rsa".to_string(),
            version: Some("0.9.0".to_string()),
            features: vec![],
            is_crypto_related: true,
        };

        // The distinction should be that AES is "used" (found in code)
        // while RSA is "implemented" (in Cargo.toml but not directly used)
        let used_algos = analyzer.extract_algorithms_from_finding(&finding);
        assert!(used_algos.contains(&"AES-256-GCM".to_string()));
        assert!(!used_algos.contains(&"RSA".to_string()));
    }
}