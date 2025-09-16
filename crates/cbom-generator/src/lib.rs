//! Minimal Viable Cryptographic Bill of Materials (MV-CBOM) Generator
//!
//! This crate implements the logic to generate a JSON document that adheres to the MV-CBOM schema.
//! The primary goal is to enable comprehensive Post-Quantum Cryptography (PQC) readiness assessment
//! and foster long-term crypto-agility.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use scanner_core::{Finding, PatternRegistry};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

pub mod algorithm_detector;
pub mod certificate_parser;
// project parsing removed

use algorithm_detector::AlgorithmDetector;
use certificate_parser::CertificateParser;
 
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

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub libraries: Vec<LibrarySummary>,
}

/// Metadata about the BOM's creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CbomMetadata {
    pub timestamp: DateTime<Utc>,
    pub tools: Vec<ToolInfo>,
}

// Component info removed to simplify schema

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

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sourceLibrary")]
    pub source_library: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<AssetEvidence>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEvidence {
    pub file: String,
    #[serde(rename = "detectorId")]
    pub detector_id: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibrarySummary {
    pub name: String,
    pub count: usize,
}

/// Classification of cryptographic primitives
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

/// Main generator for MV-CBOM documents
pub struct CbomGenerator {
    certificate_parser: CertificateParser,
    algorithm_detector: AlgorithmDetector,
    deterministic: bool,
}

impl CbomGenerator {
    pub fn new() -> Self {
        Self {
            certificate_parser: CertificateParser::new(),
            algorithm_detector: AlgorithmDetector::new(),
            deterministic: false,
        }
    }

    pub fn with_registry(registry: Arc<PatternRegistry>) -> Self {
        Self {
            certificate_parser: CertificateParser::new(),
            algorithm_detector: AlgorithmDetector::with_registry(registry),
            deterministic: false,
        }
    }

    pub fn with_registry_mode(registry: Arc<PatternRegistry>, deterministic: bool) -> Self {
        Self {
            certificate_parser: CertificateParser::with_mode(deterministic),
            algorithm_detector: AlgorithmDetector::with_registry_and_mode(registry, deterministic),
            deterministic,
        }
    }

    /// Generate an MV-CBOM for the given directory (single project)
    pub fn generate_cbom(&self, scan_path: &Path, findings: &[Finding]) -> Result<MvCbom> {
        let scan_path = scan_path
            .canonicalize()
            .with_context(|| format!("Failed to canonicalize path: {}", scan_path.display()))?;

        // Project parsing removed; no component information included

        // Parse certificates in the directory
        let certificates = self.certificate_parser.parse_certificates(&scan_path)?;

        // Detect algorithms from findings and static analysis
        let algorithms = self
            .algorithm_detector
            .detect_algorithms(&scan_path, findings)?;

        // Build crypto assets list and libraries summary
        let mut crypto_assets = Vec::new();
        crypto_assets.extend(algorithms);
        crypto_assets.extend(certificates);

        let mut lib_counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for asset in &crypto_assets {
            if let Some(ref lib) = asset.source_library {
                *lib_counts.entry(lib.clone()).or_insert(0) += 1;
            }
        }
        let libraries: Vec<LibrarySummary> = lib_counts
            .into_iter()
            .map(|(name, count)| LibrarySummary { name, count })
            .collect();

        let cbom = MvCbom {
            bom_format: "MV-CBOM".to_string(),
            spec_version: "1.0".to_string(),
            serial_number: if self.deterministic {
                format!(
                    "urn:uuid:{}",
                    Uuid::new_v5(&Uuid::NAMESPACE_URL, b"cbom:serial")
                )
            } else {
                format!("urn:uuid:{}", Uuid::new_v4())
            },
            version: 1,
            metadata: CbomMetadata {
                timestamp: if self.deterministic {
                    DateTime::from_timestamp(0, 0).unwrap()
                } else {
                    Utc::now()
                },
                tools: vec![ToolInfo {
                    name: "cipherscope".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    vendor: "CipherScope Contributors".to_string(),
                }],
            },
            crypto_assets: { crypto_assets },
            libraries,
        };

        Ok(cbom)
    }

    /// Generate MV-CBOMs for all projects discovered recursively
    pub fn generate_cboms_recursive(
        &self,
        scan_path: &Path,
        findings: &[Finding],
    ) -> Result<Vec<(PathBuf, MvCbom)>> {
        let scan_path = scan_path
            .canonicalize()
            .with_context(|| format!("Failed to canonicalize path: {}", scan_path.display()))?;

        // Project discovery removed; just generate one CBOM for the root
        let mut cboms = Vec::new();
        cboms.push((scan_path.clone(), self.generate_cbom(&scan_path, findings)?));
        Ok(cboms)
    }

    /// Write the MV-CBOM to a JSON file
    pub fn write_cbom(&self, cbom: &MvCbom, output_path: &Path) -> Result<()> {
        let json =
            serde_json::to_string_pretty(cbom).context("Failed to serialize MV-CBOM to JSON")?;

        fs::write(output_path, json)
            .with_context(|| format!("Failed to write MV-CBOM to {}", output_path.display()))?;

        Ok(())
    }

    /// Write multiple MV-CBOMs to JSON files (one per project)
    pub fn write_cboms(&self, cboms: &[(PathBuf, MvCbom)]) -> Result<Vec<PathBuf>> {
        let mut written_files = Vec::new();

        for (project_path, cbom) in cboms {
            let output_path = project_path.join("mv-cbom.json");
            self.write_cbom(cbom, &output_path)?;
            written_files.push(output_path);
        }

        Ok(written_files)
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

    #[test]
    fn test_cbom_serialization() {
        let cbom = MvCbom {
            bom_format: "MV-CBOM".to_string(),
            spec_version: "1.0".to_string(),
            serial_number: "urn:uuid:12345678-1234-1234-1234-123456789abc".to_string(),
            version: 1,
            metadata: CbomMetadata {
                timestamp: Utc::now(),
                tools: vec![ToolInfo {
                    name: "cipherscope".to_string(),
                    version: "0.1.0".to_string(),
                    vendor: "CipherScope Contributors".to_string(),
                }],
            },
            crypto_assets: vec![],
            libraries: vec![],
        };

        let json = serde_json::to_string_pretty(&cbom).unwrap();
        println!("{}", json);

        // Verify it can be deserialized
        let _parsed: MvCbom = serde_json::from_str(&json).unwrap();
    }
}
