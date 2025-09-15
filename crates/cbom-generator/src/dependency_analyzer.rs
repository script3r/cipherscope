//! Dependency analysis for determining uses vs implements relationships

use anyhow::Result;
use scanner_core::Finding;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::{
    ComponentInfo, CryptoAsset, Dependency, DependencyType, AssetType,
    dependency_parser::ProjectDependency,
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
        project_dependencies: &[ProjectDependency],
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

        // Map project dependencies to crypto assets for "implements" relationships
        let implemented_assets = self.map_project_deps_to_assets(project_dependencies, algorithms)?;

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

    /// Map project dependencies to crypto asset references
    fn map_project_deps_to_assets(&self, project_deps: &[ProjectDependency], algorithms: &[CryptoAsset]) -> Result<Vec<String>> {
        let mut implemented_assets = Vec::new();
        let mut seen_assets = HashSet::new();

        // Create a mapping from package names to potential algorithms
        let package_to_algorithms = self.build_package_algorithm_mapping();

        for project_dep in project_deps {
            if project_dep.is_crypto_related {
                let key = format!("{}:{:?}", project_dep.name, project_dep.language);
                if let Some(algo_names) = package_to_algorithms.get(&key) {
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

    /// Build a mapping from package names to the algorithms they potentially implement
    fn build_package_algorithm_mapping(&self) -> HashMap<String, Vec<String>> {
        let mut mapping = HashMap::new();

        // Rust packages
        mapping.insert("rsa:Rust".to_string(), vec!["RSA".to_string()]);
        mapping.insert("aes-gcm:Rust".to_string(), vec!["AES-256-GCM".to_string()]);
        mapping.insert("sha2:Rust".to_string(), vec!["SHA-256".to_string(), "SHA-512".to_string()]);
        mapping.insert("p256:Rust".to_string(), vec!["ECDSA".to_string()]);

        // Java packages
        mapping.insert("org.bouncycastle:bcprov-jdk15on:Java".to_string(), vec![
            "RSA".to_string(), "ECDSA".to_string(), "AES".to_string()
        ]);

        // Python packages
        mapping.insert("cryptography:Python".to_string(), vec![
            "RSA".to_string(), "ECDSA".to_string(), "AES".to_string()
        ]);
        mapping.insert("pycryptodome:Python".to_string(), vec![
            "RSA".to_string(), "AES".to_string()
        ]);

        // JavaScript packages
        mapping.insert("crypto-js:JavaScript".to_string(), vec![
            "AES".to_string(), "SHA-256".to_string()
        ]);

        // C/C++ libraries
        mapping.insert("ssl:C".to_string(), vec![
            "RSA".to_string(), "ECDSA".to_string(), "AES".to_string()
        ]);
        mapping.insert("crypto:C".to_string(), vec![
            "RSA".to_string(), "ECDSA".to_string(), "AES".to_string()
        ]);
        mapping.insert("ssl:Cpp".to_string(), vec![
            "RSA".to_string(), "ECDSA".to_string(), "AES".to_string()
        ]);
        mapping.insert("crypto:Cpp".to_string(), vec![
            "RSA".to_string(), "ECDSA".to_string(), "AES".to_string()
        ]);

        // Go packages
        mapping.insert("golang.org/x/crypto:Go".to_string(), vec![
            "RSA".to_string(), "ECDSA".to_string(), "AES".to_string()
        ]);

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
    fn test_algorithm_extraction_from_finding() {
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

        // Test that AES is extracted from the finding
        let used_algos = analyzer.extract_algorithms_from_finding(&finding);
        assert!(used_algos.contains(&"AES-256-GCM".to_string()));
    }
}