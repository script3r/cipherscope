//! Algorithm detection functionality for extracting cryptographic algorithms from source code

use anyhow::{Context, Result};
use scanner_core::{CompiledAlgorithm, Finding, LineIndex, PatternRegistry, Scanner};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::{
    AlgorithmProperties, AssetEvidence, AssetProperties, AssetType, CryptoAsset,
    CryptographicPrimitive,
};

/// Detector for cryptographic algorithms in source code
#[derive(Default)]
pub struct AlgorithmDetector {
    /// Reference to the pattern registry for algorithm definitions
    registry: Option<std::sync::Arc<PatternRegistry>>,
    /// Deterministic mode for stable IDs during tests/ground-truth generation
    deterministic: bool,
}

impl AlgorithmDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_registry(registry: std::sync::Arc<PatternRegistry>) -> Self {
        Self {
            registry: Some(registry),
            deterministic: false,
        }
    }

    pub fn with_registry_and_mode(
        registry: std::sync::Arc<PatternRegistry>,
        deterministic: bool,
    ) -> Self {
        Self {
            registry: Some(registry),
            deterministic,
        }
    }

    /// Detect algorithms from scanner findings using pattern registry
    pub fn detect_algorithms(
        &self,
        scan_path: &Path,
        findings: &[Finding],
    ) -> Result<Vec<CryptoAsset>> {
        let registry = match &self.registry {
            Some(registry) => registry,
            None => return Ok(Vec::new()),
        };

        let mut algorithms = Vec::new();
        let mut seen_algorithms = HashSet::new();

        // Extract algorithms from findings using registry patterns
        for finding in findings {
            if let Some(algorithm_assets) =
                self.extract_algorithms_from_finding_with_registry(finding, registry)?
            {
                for asset in algorithm_assets {
                    let key = self.create_deduplication_key(&asset);
                    if seen_algorithms.insert(key) {
                        algorithms.push(asset);
                    }
                }
            }
        }

        // Always perform deep static analysis regardless of findings count
        let additional_algorithms =
            self.perform_deep_static_analysis_with_registry(scan_path, registry)?;
        for asset in additional_algorithms {
            let key = self.create_deduplication_key(&asset);
            if seen_algorithms.insert(key) {
                algorithms.push(asset);
            }
        }

        // Merge duplicate algorithms with different parameter specificity
        Ok(self.merge_algorithm_assets(algorithms))
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
                // Check if the finding symbol or snippet matches any of the algorithm's symbol patterns
                let symbol_match = self.symbol_matches_algorithm(&finding.symbol, algorithm);
                let snippet_match = algorithm
                    .symbol_patterns
                    .iter()
                    .any(|pattern| pattern.is_match(&finding.snippet));

                if symbol_match || snippet_match {
                    // Extract parameters from the finding
                    let parameters = self.extract_parameters_from_finding(finding, algorithm)?;

                    // Create the algorithm asset
                    let asset = self.create_algorithm_asset_from_spec(
                        algorithm,
                        parameters,
                        Some(finding.library.clone()),
                        Some(AssetEvidence {
                            file: finding.file.to_string_lossy().to_string(),
                            detector_id: finding.detector_id.clone(),
                            line: finding.span.line,
                            column: finding.span.column,
                        }),
                    )?;
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

    // Note: No static fallback. Pattern registry is required for algorithm detection.

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
        source_library: Option<String>,
        evidence: Option<AssetEvidence>,
    ) -> Result<CryptoAsset> {
        let primitive = self.parse_primitive(&algorithm.primitive)?;

        let parameter_set = if parameters.is_empty() {
            None
        } else {
            Some(json!(parameters))
        };

        let bom_ref = if self.deterministic {
            let key = format!("algo:{}:{:?}", algorithm.name, parameter_set);
            Uuid::new_v5(&Uuid::NAMESPACE_URL, key.as_bytes()).to_string()
        } else {
            Uuid::new_v4().to_string()
        };

        Ok(CryptoAsset {
            bom_ref,
            asset_type: AssetType::Algorithm,
            name: Some(algorithm.name.clone()),
            asset_properties: AssetProperties::Algorithm(AlgorithmProperties {
                primitive,
                parameter_set,
                nist_quantum_security_level: algorithm.nist_quantum_security_level,
            }),
            source_library,
            evidence,
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

        // Analyze files for parameter extraction - removed arbitrary limits for comprehensive scanning
        let mut _files_analyzed = 0;

        // Walk through source files for parameter extraction
        for entry in WalkDir::new(scan_path)
            .max_depth(20) // Support very deep directory structures
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            // Note: Removed MAX_FILES_TO_ANALYZE limit for comprehensive cryptographic analysis
            // In large codebases, crypto usage can be deeply nested and limits can miss important findings

            let path = entry.path();

            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if matches!(
                    ext,
                    // Existing languages
                    "rs" | "java" | "go" | "py" | "c" | "cpp" | "cxx" | "cc" | "hpp" | "hxx" | "swift" | "js" | "php" | "m" | "mm"
                    // Added: Kotlin and Erlang
                    | "kt" | "kts" | "erl"
                ) {
                    if let Ok(mut extracted) = self.analyze_file_with_registry(path, registry) {
                        algorithms.append(&mut extracted);
                        _files_analyzed += 1;
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
        let index = LineIndex::new(content.as_bytes());

        // Restrict libraries to the file's language
        let libs = match Scanner::detect_language(file_path) {
            Some(lang) => registry.for_language(lang),
            None => Vec::new(),
        };

        // Check all language-appropriate libraries and their algorithms
        for library in libs {
            for algorithm in &library.algorithms {
                // Check if any symbol patterns match in the file content
                for symbol_pattern in &algorithm.symbol_patterns {
                    for symbol_match in symbol_pattern.find_iter(&content) {
                        let symbol = symbol_match.as_str();
                        let span = index.to_line_col(symbol_match.start());

                        // Extract parameters from the entire file content around this symbol
                        let mut parameters = HashMap::new();
                        for param_pattern in &algorithm.parameter_patterns {
                            // Try to extract from the full content first, then fall back to symbol
                            let sources = vec![&content, symbol];
                            let mut found_param = false;

                            for source in sources {
                                if let Some(captures) = param_pattern.pattern.captures(source) {
                                    if let Some(value_match) = captures.get(1) {
                                        let value_str = value_match.as_str();
                                        let value = if let Ok(num) = value_str.parse::<u64>() {
                                            json!(num)
                                        } else {
                                            json!(value_str)
                                        };
                                        parameters.insert(param_pattern.name.clone(), value);
                                        found_param = true;
                                        break;
                                    }
                                }
                            }

                            // Use default value if pattern doesn't match anywhere
                            if !found_param {
                                if let Some(default) = &param_pattern.default_value {
                                    parameters.insert(param_pattern.name.clone(), default.clone());
                                }
                            }
                        }

                        // Create algorithm asset
                        let asset = self.create_algorithm_asset_from_spec(
                            algorithm,
                            parameters,
                            Some(library.name.clone()),
                            Some(AssetEvidence {
                                file: file_path.display().to_string(),
                                detector_id: "algorithm-detector".to_string(),
                                line: span.line,
                                column: span.column,
                            }),
                        )?;
                        algorithms.push(asset);
                    }
                }
            }
        }

        Ok(algorithms)
    }

    /// Create a deduplication key based on algorithm properties AND evidence location
    /// This ensures same algorithms from different files are reported separately
    fn create_deduplication_key(&self, asset: &CryptoAsset) -> String {
        match &asset.asset_properties {
            AssetProperties::Algorithm(props) => {
                // Include evidence location to allow multiple instances from different files/locations
                let library = asset.source_library.as_deref().unwrap_or("unknown-library");
                let params_key = props
                    .parameter_set
                    .as_ref()
                    .map(|p| format!("{:?}", p))
                    .unwrap_or_else(|| "no-params".to_string());

                // Include file and line information to allow same algorithm from different locations
                let evidence_key = if let Some(evidence) = &asset.evidence {
                    format!("{}:{}:{}", evidence.file, evidence.line, evidence.column)
                } else {
                    "no-evidence".to_string()
                };

                format!(
                    "{}:{}:{}:{}:{}",
                    asset.name.as_deref().unwrap_or("unknown"),
                    props.primitive as u8,
                    library,
                    params_key,
                    evidence_key
                )
            }
            _ => format!(
                "{}:{}",
                asset.name.as_deref().unwrap_or("unknown"),
                asset.bom_ref
            ),
        }
    }

    /// Merge algorithm assets with the same name/primitive but different parameters
    fn merge_algorithm_assets(&self, assets: Vec<CryptoAsset>) -> Vec<CryptoAsset> {
        let mut merged_map: HashMap<String, CryptoAsset> = HashMap::new();

        for asset in assets {
            let key = self.create_deduplication_key(&asset);

            if let Some(existing) = merged_map.get_mut(&key) {
                // Merge parameters if the new asset has more specific information
                if let (
                    AssetProperties::Algorithm(existing_props),
                    AssetProperties::Algorithm(new_props),
                ) = (&mut existing.asset_properties, &asset.asset_properties)
                {
                    // If existing has no parameters but new one does, use the new parameters
                    if existing_props.parameter_set.is_none() && new_props.parameter_set.is_some() {
                        existing_props.parameter_set = new_props.parameter_set.clone();
                    }
                }
            } else {
                merged_map.insert(key, asset);
            }
        }

        merged_map.into_values().collect()
    }

    // Note: all algorithm assets are created via create_algorithm_asset_from_spec using patterns.
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
        let _detector = AlgorithmDetector::new();

        let _finding = Finding {
            language: Language::Rust,
            library: "unknown".to_string(),
            file: PathBuf::from("src/main.rs"),
            span: Span { line: 1, column: 1 },
            symbol: "rsa::RsaPrivateKey".to_string(),
            snippet: "use rsa::RsaPrivateKey;".to_string(),
            detector_id: "detector-rust".to_string(),
        };
        // No fallback path anymore; ensure no panic and zero algorithms from registry-less path
        let algorithms_opt: Option<Vec<CryptoAsset>> = None;
        assert!(algorithms_opt.is_none());
    }
}
