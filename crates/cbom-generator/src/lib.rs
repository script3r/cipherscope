//! Minimal Viable Cryptographic Bill of Materials (MV-CBOM) Generator
//!
//! This crate implements the logic to generate a JSON document that adheres to the MV-CBOM schema.
//! The primary goal is to enable comprehensive Post-Quantum Cryptography (PQC) readiness assessment
//! and foster long-term crypto-agility.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use scanner_core::Finding;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub mod certificate_parser;
pub mod dependency_analyzer;
pub mod algorithm_detector;
pub mod project_parser;

use certificate_parser::CertificateParser;
use dependency_analyzer::DependencyAnalyzer;
use algorithm_detector::AlgorithmDetector;
use project_parser::ProjectParser;

/// The main MV-CBOM document structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MvCbom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String, // Fixed value: "MV-CBOM"
    
    #[serde(rename = "specVersion")]
    pub spec_version: String, // e.g., "1.0"
    
    #[serde(rename = "serialNumber")]
    pub serial_number: String, // URN UUID format
    
    pub version: u32, // Increments with each new version
    
    pub metadata: CbomMetadata,
    
    #[serde(rename = "cryptoAssets")]
    pub crypto_assets: Vec<CryptoAsset>,
    
    pub dependencies: Vec<Dependency>,
}

/// Metadata about the BOM's creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomMetadata {
    pub component: ComponentInfo,
    pub timestamp: DateTime<Utc>,
    pub tools: Vec<ToolInfo>,
}

/// Information about the software component being scanned
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub path: String, // Absolute path that was scanned
}

/// Information about the tool that generated the BOM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub vendor: String,
}

/// A cryptographic asset discovered in the codebase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAsset {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String, // Locally unique identifier (UUID)
    
    #[serde(rename = "assetType")]
    pub asset_type: AssetType,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>, // Human-readable name
    
    #[serde(rename = "assetProperties")]
    pub asset_properties: AssetProperties,
}

/// The type classification of a cryptographic asset
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AssetType {
    Algorithm,
    Certificate,
    RelatedCryptoMaterial,
}

/// Properties specific to the asset type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AssetProperties {
    Algorithm(AlgorithmProperties),
    Certificate(CertificateProperties),
    RelatedCryptoMaterial(RelatedCryptoMaterialProperties),
}

/// Properties for algorithm assets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmProperties {
    pub primitive: CryptographicPrimitive,
    
    #[serde(rename = "parameterSet")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_set: Option<serde_json::Value>, // Flexible parameter storage
    
    #[serde(rename = "nistQuantumSecurityLevel")]
    pub nist_quantum_security_level: u8, // 0 for vulnerable, 1-5 for secure
}

/// Properties for certificate assets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateProperties {
    #[serde(rename = "subjectName")]
    pub subject_name: String,
    
    #[serde(rename = "issuerName")]
    pub issuer_name: String,
    
    #[serde(rename = "notValidAfter")]
    pub not_valid_after: DateTime<Utc>,
    
    #[serde(rename = "signatureAlgorithmRef")]
    pub signature_algorithm_ref: String, // bom-ref to algorithm asset
}

/// Properties for related cryptographic material
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedCryptoMaterialProperties {
    #[serde(rename = "materialType")]
    pub material_type: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Classification of cryptographic primitives
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CryptographicPrimitive {
    #[serde(rename = "pke")]
    PublicKeyEncryption,
    Signature,
    Hash,
    #[serde(rename = "kem")]
    KeyEncapsulationMechanism,
    #[serde(rename = "aead")]
    AuthenticatedEncryption,
    #[serde(rename = "mac")]
    MessageAuthenticationCode,
    #[serde(rename = "kdf")]
    KeyDerivationFunction,
    #[serde(rename = "prng")]
    PseudoRandomNumberGenerator,
}

/// Relationship between components and cryptographic assets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub ref_: String, // bom-ref of the component that has the dependency
    
    #[serde(rename = "dependsOn")]
    pub depends_on: Vec<String>, // bom-refs that the ref component depends on
    
    #[serde(rename = "dependencyType")]
    pub dependency_type: DependencyType,
}

/// The nature of the dependency relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyType {
    Uses,       // Direct invocation in source code or certificate usage
    Implements, // Library is present but not directly called
}

/// Main generator for MV-CBOM documents
pub struct CbomGenerator {
    certificate_parser: CertificateParser,
    dependency_analyzer: DependencyAnalyzer,
    algorithm_detector: AlgorithmDetector,
    project_parser: ProjectParser,
}

impl CbomGenerator {
    pub fn new() -> Self {
        Self {
            certificate_parser: CertificateParser::new(),
            dependency_analyzer: DependencyAnalyzer::new(),
            algorithm_detector: AlgorithmDetector::new(),
            project_parser: ProjectParser::new(),
        }
    }

    /// Generate an MV-CBOM for the given directory
    pub fn generate_cbom(&self, scan_path: &Path, findings: &[Finding]) -> Result<MvCbom> {
        let scan_path = scan_path.canonicalize()
            .with_context(|| format!("Failed to canonicalize path: {}", scan_path.display()))?;

        // Parse project information and dependencies from various project files
        let (project_info, project_dependencies) = self.project_parser.parse_project(&scan_path)?;
        
        // Create component info from parsed project information
        let component_info = ComponentInfo {
            name: project_info.name,
            version: project_info.version,
            path: scan_path.display().to_string(),
        };
        
        // Parse certificates in the directory
        let certificates = self.certificate_parser.parse_certificates(&scan_path)?;
        
        // Detect algorithms from findings and static analysis
        let algorithms = self.algorithm_detector.detect_algorithms(&scan_path, findings)?;
        
        // Analyze dependencies (uses vs implements) with project dependencies
        let dependencies = self.dependency_analyzer.analyze_dependencies(
            &component_info,
            &algorithms,
            &certificates,
            &project_dependencies,
            findings,
        )?;

        // Build crypto assets list
        let mut crypto_assets = Vec::new();
        crypto_assets.extend(algorithms);
        crypto_assets.extend(certificates);

        let cbom = MvCbom {
            bom_format: "MV-CBOM".to_string(),
            spec_version: "1.0".to_string(),
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            metadata: CbomMetadata {
                component: component_info,
                timestamp: Utc::now(),
                tools: vec![ToolInfo {
                    name: "cipherscope".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    vendor: "CipherScope Contributors".to_string(),
                }],
            },
            crypto_assets,
            dependencies,
        };

        Ok(cbom)
    }


    /// Write the MV-CBOM to a JSON file
    pub fn write_cbom(&self, cbom: &MvCbom, output_path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(cbom)
            .context("Failed to serialize MV-CBOM to JSON")?;
        
        fs::write(output_path, json)
            .with_context(|| format!("Failed to write MV-CBOM to {}", output_path.display()))?;
        
        Ok(())
    }
}

impl Default for CbomGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cbom_serialization() {
        let cbom = MvCbom {
            bom_format: "MV-CBOM".to_string(),
            spec_version: "1.0".to_string(),
            serial_number: "urn:uuid:12345678-1234-1234-1234-123456789abc".to_string(),
            version: 1,
            metadata: CbomMetadata {
                component: ComponentInfo {
                    name: "test-project".to_string(),
                    version: Some("0.1.0".to_string()),
                    path: "/tmp/test".to_string(),
                },
                timestamp: Utc::now(),
                tools: vec![ToolInfo {
                    name: "cipherscope".to_string(),
                    version: "0.1.0".to_string(),
                    vendor: "CipherScope Contributors".to_string(),
                }],
            },
            crypto_assets: vec![],
            dependencies: vec![],
        };

        let json = serde_json::to_string_pretty(&cbom).unwrap();
        println!("{}", json);
        
        // Verify it can be deserialized
        let _parsed: MvCbom = serde_json::from_str(&json).unwrap();
    }
}