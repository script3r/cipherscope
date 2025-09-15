//! Cargo.toml parsing functionality for extracting project information and dependencies

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Information about a Cargo dependency
#[derive(Debug, Clone)]
pub struct CargoDependency {
    pub name: String,
    pub version: Option<String>,
    pub features: Vec<String>,
    pub is_crypto_related: bool,
}

/// Parser for Cargo.toml files
pub struct CargoParser {
    /// Known cryptographic crates and their classifications
    crypto_crates: HashMap<String, CrateClassification>,
}

/// Classification of a cryptographic crate
#[derive(Debug, Clone)]
pub struct CrateClassification {
    pub algorithms: Vec<String>,
    pub is_pqc_vulnerable: bool,
    pub description: String,
}

impl CargoParser {
    pub fn new() -> Self {
        let mut crypto_crates = HashMap::new();
        
        // Populate known cryptographic crates
        Self::populate_crypto_crates(&mut crypto_crates);
        
        Self { crypto_crates }
    }

    /// Parse project information from Cargo.toml
    pub fn parse_project_info(&self, cargo_toml_path: &Path) -> Result<(String, Option<String>)> {
        let content = fs::read_to_string(cargo_toml_path)
            .with_context(|| format!("Failed to read Cargo.toml: {}", cargo_toml_path.display()))?;

        let cargo_toml: CargoToml = toml::from_str(&content)
            .context("Failed to parse Cargo.toml")?;

        let name = cargo_toml.package.name;
        let version = cargo_toml.package.version;

        Ok((name, Some(version)))
    }

    /// Parse dependencies from Cargo.toml
    pub fn parse_cargo_dependencies(&self, scan_path: &Path) -> Result<Vec<CargoDependency>> {
        let cargo_toml_path = scan_path.join("Cargo.toml");
        
        if !cargo_toml_path.exists() {
            return Ok(Vec::new()); // No Cargo.toml found
        }

        let content = fs::read_to_string(&cargo_toml_path)
            .with_context(|| format!("Failed to read Cargo.toml: {}", cargo_toml_path.display()))?;

        let cargo_toml: CargoToml = toml::from_str(&content)
            .context("Failed to parse Cargo.toml")?;

        let mut dependencies = Vec::new();

        // Parse regular dependencies
        if let Some(deps) = cargo_toml.dependencies {
            for (name, dep_spec) in deps {
                let dependency = self.parse_dependency_spec(&name, &dep_spec)?;
                dependencies.push(dependency);
            }
        }

        // Parse dev dependencies
        if let Some(dev_deps) = cargo_toml.dev_dependencies {
            for (name, dep_spec) in dev_deps {
                let dependency = self.parse_dependency_spec(&name, &dep_spec)?;
                dependencies.push(dependency);
            }
        }

        // Parse build dependencies
        if let Some(build_deps) = cargo_toml.build_dependencies {
            for (name, dep_spec) in build_deps {
                let dependency = self.parse_dependency_spec(&name, &dep_spec)?;
                dependencies.push(dependency);
            }
        }

        Ok(dependencies)
    }

    /// Parse a dependency specification from Cargo.toml
    fn parse_dependency_spec(&self, name: &str, spec: &DependencySpec) -> Result<CargoDependency> {
        let (version, features) = match spec {
            DependencySpec::Simple(version) => (Some(version.clone()), Vec::new()),
            DependencySpec::Detailed(detailed) => {
                let version = detailed.version.clone();
                let features = detailed.features.clone().unwrap_or_default();
                (version, features)
            }
        };

        let is_crypto_related = self.is_crypto_crate(name);

        Ok(CargoDependency {
            name: name.to_string(),
            version,
            features,
            is_crypto_related,
        })
    }

    /// Check if a crate is cryptography-related
    pub fn is_crypto_crate(&self, crate_name: &str) -> bool {
        self.crypto_crates.contains_key(crate_name)
    }

    /// Get classification for a crypto crate
    pub fn get_crate_classification(&self, crate_name: &str) -> Option<&CrateClassification> {
        self.crypto_crates.get(crate_name)
    }

    /// Populate the database of known cryptographic crates
    fn populate_crypto_crates(crypto_crates: &mut HashMap<String, CrateClassification>) {
        // RSA crates - vulnerable to quantum attacks
        crypto_crates.insert("rsa".to_string(), CrateClassification {
            algorithms: vec!["RSA".to_string()],
            is_pqc_vulnerable: true,
            description: "RSA implementation".to_string(),
        });

        // ECDSA/ECC crates - vulnerable to quantum attacks
        crypto_crates.insert("p256".to_string(), CrateClassification {
            algorithms: vec!["ECDSA".to_string(), "ECDH".to_string()],
            is_pqc_vulnerable: true,
            description: "P-256 elliptic curve implementation".to_string(),
        });

        crypto_crates.insert("p384".to_string(), CrateClassification {
            algorithms: vec!["ECDSA".to_string(), "ECDH".to_string()],
            is_pqc_vulnerable: true,
            description: "P-384 elliptic curve implementation".to_string(),
        });

        crypto_crates.insert("k256".to_string(), CrateClassification {
            algorithms: vec!["ECDSA".to_string()],
            is_pqc_vulnerable: true,
            description: "secp256k1 elliptic curve implementation".to_string(),
        });

        // Ed25519 - vulnerable to quantum attacks
        crypto_crates.insert("ed25519-dalek".to_string(), CrateClassification {
            algorithms: vec!["Ed25519".to_string()],
            is_pqc_vulnerable: true,
            description: "Ed25519 digital signatures".to_string(),
        });

        crypto_crates.insert("curve25519-dalek".to_string(), CrateClassification {
            algorithms: vec!["X25519".to_string(), "Ed25519".to_string()],
            is_pqc_vulnerable: true,
            description: "Curve25519 implementation".to_string(),
        });

        // Symmetric crypto - generally quantum-safe with sufficient key sizes
        crypto_crates.insert("aes".to_string(), CrateClassification {
            algorithms: vec!["AES".to_string()],
            is_pqc_vulnerable: false,
            description: "AES block cipher".to_string(),
        });

        crypto_crates.insert("aes-gcm".to_string(), CrateClassification {
            algorithms: vec!["AES-GCM".to_string()],
            is_pqc_vulnerable: false,
            description: "AES-GCM authenticated encryption".to_string(),
        });

        crypto_crates.insert("chacha20".to_string(), CrateClassification {
            algorithms: vec!["ChaCha20".to_string()],
            is_pqc_vulnerable: false,
            description: "ChaCha20 stream cipher".to_string(),
        });

        crypto_crates.insert("chacha20poly1305".to_string(), CrateClassification {
            algorithms: vec!["ChaCha20Poly1305".to_string()],
            is_pqc_vulnerable: false,
            description: "ChaCha20Poly1305 AEAD".to_string(),
        });

        // Hash functions - generally quantum-resistant with sufficient output size
        crypto_crates.insert("sha2".to_string(), CrateClassification {
            algorithms: vec!["SHA-256".to_string(), "SHA-384".to_string(), "SHA-512".to_string()],
            is_pqc_vulnerable: false,
            description: "SHA-2 hash functions".to_string(),
        });

        crypto_crates.insert("sha3".to_string(), CrateClassification {
            algorithms: vec!["SHA-3".to_string(), "SHAKE".to_string()],
            is_pqc_vulnerable: false,
            description: "SHA-3 hash functions".to_string(),
        });

        crypto_crates.insert("blake2".to_string(), CrateClassification {
            algorithms: vec!["BLAKE2b".to_string(), "BLAKE2s".to_string()],
            is_pqc_vulnerable: false,
            description: "BLAKE2 hash functions".to_string(),
        });

        crypto_crates.insert("blake3".to_string(), CrateClassification {
            algorithms: vec!["BLAKE3".to_string()],
            is_pqc_vulnerable: false,
            description: "BLAKE3 hash function".to_string(),
        });

        // High-level crypto libraries
        crypto_crates.insert("ring".to_string(), CrateClassification {
            algorithms: vec!["RSA".to_string(), "ECDSA".to_string(), "AES".to_string(), "ChaCha20Poly1305".to_string()],
            is_pqc_vulnerable: true, // Contains vulnerable algorithms
            description: "Safe, fast crypto using BoringSSL".to_string(),
        });

        crypto_crates.insert("openssl".to_string(), CrateClassification {
            algorithms: vec!["RSA".to_string(), "ECDSA".to_string(), "AES".to_string()],
            is_pqc_vulnerable: true, // Contains vulnerable algorithms
            description: "OpenSSL bindings".to_string(),
        });

        // Post-quantum cryptography (when available)
        crypto_crates.insert("kyber".to_string(), CrateClassification {
            algorithms: vec!["ML-KEM".to_string()],
            is_pqc_vulnerable: false,
            description: "ML-KEM (Kyber) post-quantum KEM".to_string(),
        });

        crypto_crates.insert("dilithium".to_string(), CrateClassification {
            algorithms: vec!["ML-DSA".to_string()],
            is_pqc_vulnerable: false,
            description: "ML-DSA (Dilithium) post-quantum signatures".to_string(),
        });

        // Password hashing
        crypto_crates.insert("argon2".to_string(), CrateClassification {
            algorithms: vec!["Argon2".to_string()],
            is_pqc_vulnerable: false,
            description: "Argon2 password hashing".to_string(),
        });

        crypto_crates.insert("scrypt".to_string(), CrateClassification {
            algorithms: vec!["scrypt".to_string()],
            is_pqc_vulnerable: false,
            description: "scrypt password hashing".to_string(),
        });

        crypto_crates.insert("bcrypt".to_string(), CrateClassification {
            algorithms: vec!["bcrypt".to_string()],
            is_pqc_vulnerable: false,
            description: "bcrypt password hashing".to_string(),
        });
    }
}

impl Default for CargoParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Simplified Cargo.toml structure for parsing
#[derive(Debug, Deserialize)]
struct CargoToml {
    package: Package,
    #[serde(default)]
    dependencies: Option<HashMap<String, DependencySpec>>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: Option<HashMap<String, DependencySpec>>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: Option<HashMap<String, DependencySpec>>,
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DependencySpec {
    Simple(String),
    Detailed(DetailedDependency),
}

#[derive(Debug, Deserialize)]
struct DetailedDependency {
    version: Option<String>,
    features: Option<Vec<String>>,
    #[serde(default)]
    #[allow(dead_code)]
    optional: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_cargo_parser_creation() {
        let parser = CargoParser::new();
        assert!(parser.is_crypto_crate("rsa"));
        assert!(parser.is_crypto_crate("aes-gcm"));
        assert!(!parser.is_crypto_crate("serde"));
    }

    #[test]
    fn test_parse_simple_cargo_toml() {
        let cargo_content = r#"
[package]
name = "test-project"
version = "0.1.0"

[dependencies]
serde = "1.0"
aes-gcm = "0.10"
rsa = { version = "0.9", features = ["sha2"] }
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(cargo_content.as_bytes()).unwrap();
        
        let parser = CargoParser::new();
        let (name, version) = parser.parse_project_info(temp_file.path()).unwrap();
        
        assert_eq!(name, "test-project");
        assert_eq!(version, Some("0.1.0".to_string()));
    }

    #[test]
    fn test_crypto_crate_classification() {
        let parser = CargoParser::new();
        
        // Test RSA (vulnerable)
        let rsa_class = parser.get_crate_classification("rsa").unwrap();
        assert!(rsa_class.is_pqc_vulnerable);
        assert!(rsa_class.algorithms.contains(&"RSA".to_string()));
        
        // Test AES (not vulnerable)
        let aes_class = parser.get_crate_classification("aes").unwrap();
        assert!(!aes_class.is_pqc_vulnerable);
        assert!(aes_class.algorithms.contains(&"AES".to_string()));
    }
}