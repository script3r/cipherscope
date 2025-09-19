//! Simple JSONL output format for cryptographic findings
//!
//! This module provides a simplified output format that emits one JSON object per line (JSONL)
//! instead of the complex MV-CBOM format.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{Finding, Language};

/// Simple cryptographic finding for JSONL output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoFinding {
    /// Programming language of the source file
    pub language: Language,
    
    /// Cryptographic library detected
    pub library: String,
    
    /// Algorithm or API symbol found
    pub symbol: String,
    
    /// File path where the finding was detected
    pub file: PathBuf,
    
    /// Line number in the file (1-based)
    pub line: usize,
    
    /// Column number in the file (1-based)
    pub column: usize,
    
    /// Code snippet containing the finding
    pub snippet: String,
    
    /// Detector that found this result
    pub detector: String,
    
    /// Algorithm type if detected (signature, aead, hash, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_type: Option<String>,
    
    /// NIST quantum security level (0 = vulnerable, 1-5 = secure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantum_security_level: Option<u8>,
    
    /// Additional parameters extracted (key size, curve, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
}

impl From<Finding> for CryptoFinding {
    fn from(finding: Finding) -> Self {
        Self {
            language: finding.language,
            library: finding.library,
            symbol: finding.symbol,
            file: finding.file,
            line: finding.span.line,
            column: finding.span.column,
            snippet: finding.snippet,
            detector: finding.detector_id,
            algorithm_type: None,
            quantum_security_level: None,
            parameters: None,
        }
    }
}

impl CryptoFinding {
    /// Create a new finding with algorithm information
    pub fn with_algorithm_info(
        mut self, 
        algorithm_type: String, 
        quantum_level: u8,
        parameters: Option<serde_json::Value>
    ) -> Self {
        self.algorithm_type = Some(algorithm_type);
        self.quantum_security_level = Some(quantum_level);
        self.parameters = parameters;
        self
    }
    
    /// Serialize to a JSONL line (single line JSON)
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
    
    /// Parse from a JSONL line
    pub fn from_jsonl_line(line: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(line)
    }
}

/// Collection of crypto findings with utility methods
#[derive(Debug, Clone)]
pub struct CryptoFindings {
    pub findings: Vec<CryptoFinding>,
}

impl CryptoFindings {
    pub fn new() -> Self {
        Self { findings: Vec::new() }
    }
    
    pub fn from_scanner_findings(scanner_findings: Vec<Finding>) -> Self {
        let findings = scanner_findings.into_iter()
            .map(CryptoFinding::from)
            .collect();
        Self { findings }
    }
    
    /// Add a finding to the collection
    pub fn add(&mut self, finding: CryptoFinding) {
        self.findings.push(finding);
    }
    
    /// Get count of findings
    pub fn len(&self) -> usize {
        self.findings.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
    
    /// Convert all findings to JSONL format (one JSON object per line)
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        let lines: Result<Vec<String>, _> = self.findings.iter()
            .map(|f| f.to_jsonl_line())
            .collect();
        Ok(lines?.join("\n"))
    }
    
    /// Parse JSONL format back to findings
    pub fn from_jsonl(jsonl: &str) -> Result<Self, serde_json::Error> {
        let findings: Result<Vec<CryptoFinding>, _> = jsonl.lines()
            .filter(|line| !line.trim().is_empty())
            .map(CryptoFinding::from_jsonl_line)
            .collect();
        Ok(Self { findings: findings? })
    }
    
    /// Get unique libraries found
    pub fn get_libraries(&self) -> Vec<String> {
        let mut libraries: Vec<String> = self.findings.iter()
            .map(|f| f.library.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        libraries.sort();
        libraries
    }
    
    /// Get unique algorithms found
    pub fn get_algorithms(&self) -> Vec<String> {
        let mut algorithms: Vec<String> = self.findings.iter()
            .filter_map(|f| f.algorithm_type.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        algorithms.sort();
        algorithms
    }
    
    /// Filter findings by language
    pub fn filter_by_language(&self, language: Language) -> Self {
        let findings = self.findings.iter()
            .filter(|f| f.language == language)
            .cloned()
            .collect();
        Self { findings }
    }
    
    /// Filter findings by library
    pub fn filter_by_library(&self, library: &str) -> Self {
        let findings = self.findings.iter()
            .filter(|f| f.library == library)
            .cloned()
            .collect();
        Self { findings }
    }
    
    /// Get findings with quantum vulnerability (level 0)
    pub fn get_quantum_vulnerable(&self) -> Self {
        let findings = self.findings.iter()
            .filter(|f| f.quantum_security_level == Some(0))
            .cloned()
            .collect();
        Self { findings }
    }
}

impl Default for CryptoFindings {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Span;
    use std::path::PathBuf;
    
    #[test]
    fn test_crypto_finding_serialization() {
        let finding = CryptoFinding {
            language: Language::Rust,
            library: "ring".to_string(),
            symbol: "digest::digest".to_string(),
            file: PathBuf::from("src/main.rs"),
            line: 42,
            column: 10,
            snippet: "digest::digest(&SHA256, data)".to_string(),
            detector: "ast-detector".to_string(),
            algorithm_type: Some("hash".to_string()),
            quantum_security_level: Some(3),
            parameters: Some(serde_json::json!({"output_size": 256})),
        };
        
        let jsonl_line = finding.to_jsonl_line().unwrap();
        assert!(jsonl_line.contains("ring"));
        assert!(jsonl_line.contains("digest::digest"));
        
        let parsed = CryptoFinding::from_jsonl_line(&jsonl_line).unwrap();
        assert_eq!(parsed.library, "ring");
        assert_eq!(parsed.symbol, "digest::digest");
        assert_eq!(parsed.quantum_security_level, Some(3));
    }
    
    #[test]
    fn test_crypto_findings_collection() {
        let mut findings = CryptoFindings::new();
        
        let finding1 = CryptoFinding {
            language: Language::C,
            library: "OpenSSL".to_string(),
            symbol: "RSA_new".to_string(),
            file: PathBuf::from("crypto.c"),
            line: 10,
            column: 5,
            snippet: "RSA *rsa = RSA_new();".to_string(),
            detector: "ast-detector".to_string(),
            algorithm_type: Some("signature".to_string()),
            quantum_security_level: Some(0),
            parameters: None,
        };
        
        let finding2 = CryptoFinding {
            language: Language::C,
            library: "OpenSSL".to_string(),
            symbol: "EVP_aes_256_gcm".to_string(),
            file: PathBuf::from("crypto.c"),
            line: 15,
            column: 8,
            snippet: "EVP_aes_256_gcm()".to_string(),
            detector: "ast-detector".to_string(),
            algorithm_type: Some("aead".to_string()),
            quantum_security_level: Some(3),
            parameters: Some(serde_json::json!({"key_size": 256})),
        };
        
        findings.add(finding1);
        findings.add(finding2);
        
        assert_eq!(findings.len(), 2);
        assert_eq!(findings.get_libraries(), vec!["OpenSSL"]);
        assert_eq!(findings.get_algorithms(), vec!["aead", "signature"]);
        
        let vulnerable = findings.get_quantum_vulnerable();
        assert_eq!(vulnerable.len(), 1);
        assert_eq!(vulnerable.findings[0].symbol, "RSA_new");
    }
    
    #[test]
    fn test_jsonl_roundtrip() {
        let finding = CryptoFinding {
            language: Language::Python,
            library: "cryptography".to_string(),
            symbol: "Fernet".to_string(),
            file: PathBuf::from("app.py"),
            line: 5,
            column: 1,
            snippet: "from cryptography.fernet import Fernet".to_string(),
            detector: "ast-detector".to_string(),
            algorithm_type: Some("aead".to_string()),
            quantum_security_level: Some(3),
            parameters: None,
        };
        
        let mut findings = CryptoFindings::new();
        findings.add(finding.clone());
        
        let jsonl = findings.to_jsonl().unwrap();
        let parsed_findings = CryptoFindings::from_jsonl(&jsonl).unwrap();
        
        assert_eq!(parsed_findings.len(), 1);
        assert_eq!(parsed_findings.findings[0].library, finding.library);
        assert_eq!(parsed_findings.findings[0].symbol, finding.symbol);
    }
}