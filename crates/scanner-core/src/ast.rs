//! AST-based detection for cryptographic libraries and algorithms
//!
//! This module provides AST parsing and matching capabilities to detect:
//! 1. Libraries via import/include/using statements 
//! 2. Algorithms via method names, function calls, and type definitions

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tree_sitter::{Language, Parser, Query, QueryCursor, Tree};

use crate::{Language as ScanLanguage, ScanUnit, Finding, Span, Emitter};


/// AST-based pattern matching for cryptographic detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstPattern {
    /// Tree-sitter query string for matching AST nodes
    pub query: String,
    /// Language this pattern applies to
    pub language: ScanLanguage,
    /// What type of match this represents (library, algorithm)
    pub match_type: AstMatchType,
    /// Optional metadata for the match
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AstMatchType {
    /// Library import/include detection
    Library { name: String },
    /// Algorithm usage detection  
    Algorithm { 
        name: String, 
        primitive: String,
        nist_quantum_security_level: u8,
    },
}

/// AST-based detector that replaces regex pattern matching
pub struct AstDetector {
    /// Tree-sitter parsers for each language
    parsers: HashMap<ScanLanguage, Parser>,
    /// AST patterns to match against
    patterns: Vec<AstPattern>,
}

impl AstDetector {
    pub fn new() -> Result<Self> {
        let mut parsers = HashMap::new();
        
        // Initialize parsers for supported languages (known working versions)
        parsers.insert(ScanLanguage::C, Self::create_parser(tree_sitter_c::language())?);
        parsers.insert(ScanLanguage::Cpp, Self::create_parser(tree_sitter_cpp::language())?);
        parsers.insert(ScanLanguage::Rust, Self::create_parser(tree_sitter_rust::language())?);
        parsers.insert(ScanLanguage::Python, Self::create_parser(tree_sitter_python::language())?);
        parsers.insert(ScanLanguage::Java, Self::create_parser(tree_sitter_java::language())?);
        parsers.insert(ScanLanguage::Go, Self::create_parser(tree_sitter_go::language())?);
        
        // Additional languages can be added here as tree-sitter parsers become compatible
        
        Ok(Self {
            parsers,
            patterns: Self::default_patterns(),
        })
    }
    
    fn create_parser(language: Language) -> Result<Parser> {
        let mut parser = Parser::new();
        parser.set_language(&language)
            .map_err(|e| anyhow!("Failed to set parser language: {}", e))?;
        Ok(parser)
    }
    
    
    
    
    /// Load AST patterns from patterns.toml or use defaults
    pub fn load_patterns_from_file(patterns_file: &str) -> Result<Vec<AstPattern>> {
        let patterns_content = std::fs::read_to_string(patterns_file)?;
        Self::load_patterns_from_toml(&patterns_content)
    }
    
    /// Load AST patterns from TOML content
    pub fn load_patterns_from_toml(toml_content: &str) -> Result<Vec<AstPattern>> {
        use crate::PatternsFile;
        
        let patterns_file: PatternsFile = toml::from_str(toml_content)?;
        let mut ast_patterns = Vec::new();
        
        // Convert library specs to AST patterns
        for library in patterns_file.library {
            ast_patterns.extend(Self::convert_library_to_ast_patterns(&library)?);
        }
        
        // Also include default patterns for comprehensive coverage
        ast_patterns.extend(Self::default_patterns());
        
        Ok(ast_patterns)
    }
    
    /// Convert a library specification to AST patterns
    fn convert_library_to_ast_patterns(library: &crate::LibrarySpec) -> Result<Vec<AstPattern>> {
        let mut patterns = Vec::new();
        
        for &language in &library.languages {
            // Convert include patterns to AST patterns
            for pattern in &library.patterns.include_patterns {
                patterns.push(AstPattern {
                    query: pattern.clone(),
                    language,
                    match_type: AstMatchType::Library { name: library.name.clone() },
                    metadata: HashMap::new(),
                });
            }
            
            // Convert import patterns to AST patterns
            for pattern in &library.patterns.import_patterns {
                patterns.push(AstPattern {
                    query: pattern.clone(),
                    language,
                    match_type: AstMatchType::Library { name: library.name.clone() },
                    metadata: HashMap::new(),
                });
            }
            
            // Convert algorithm patterns
            for algorithm in &library.algorithms {
                for pattern in &algorithm.symbol_patterns {
                    patterns.push(AstPattern {
                        query: pattern.clone(),
                        language,
                        match_type: AstMatchType::Algorithm {
                            name: algorithm.name.clone(),
                            primitive: algorithm.primitive.clone(),
                            nist_quantum_security_level: algorithm.nist_quantum_security_level,
                        },
                        metadata: HashMap::new(),
                    });
                }
            }
        }
        
        Ok(patterns)
    }
    
    /// Default AST patterns for common cryptographic libraries and algorithms
    fn default_patterns() -> Vec<AstPattern> {
        vec![
            // C/C++ OpenSSL library detection
            AstPattern {
                query: r#"
                    (preproc_include 
                      path: (system_lib_string) @path
                      (#match? @path "openssl/.*"))
                "#.to_string(),
                language: ScanLanguage::C,
                match_type: AstMatchType::Library { name: "OpenSSL".to_string() },
                metadata: HashMap::new(),
            },
            
            // C/C++ OpenSSL RSA function calls
            AstPattern {
                query: r#"
                    (call_expression
                      function: (identifier) @func
                      (#match? @func "RSA_.*|EVP_PKEY_RSA.*"))
                "#.to_string(),
                language: ScanLanguage::C,
                match_type: AstMatchType::Algorithm { 
                    name: "RSA".to_string(),
                    primitive: "signature".to_string(),
                    nist_quantum_security_level: 0,
                },
                metadata: HashMap::new(),
            },
            
            // C/C++ OpenSSL AES function calls
            AstPattern {
                query: r#"
                    (call_expression
                      function: (identifier) @func
                      (#match? @func "EVP_aes_.*|AES_.*"))
                "#.to_string(),
                language: ScanLanguage::C,
                match_type: AstMatchType::Algorithm { 
                    name: "AES".to_string(),
                    primitive: "aead".to_string(),
                    nist_quantum_security_level: 3,
                },
                metadata: HashMap::new(),
            },
            
            // Rust ring crate imports
            AstPattern {
                query: r#"
                    (use_declaration
                      argument: (scoped_identifier
                        path: (identifier) @crate
                        (#eq? @crate "ring")))
                "#.to_string(),
                language: ScanLanguage::Rust,
                match_type: AstMatchType::Library { name: "ring".to_string() },
                metadata: HashMap::new(),
            },
            
            // Rust crypto crate imports
            AstPattern {
                query: r#"
                    (use_declaration
                      argument: (identifier) @crate
                      (#match? @crate "aes_gcm|sha2|rsa|hmac"))
                "#.to_string(),
                language: ScanLanguage::Rust,
                match_type: AstMatchType::Library { name: "rust-crypto".to_string() },
                metadata: HashMap::new(),
            },
            
            // Rust ring module usage (e.g., ring::digest::SHA256)
            AstPattern {
                query: r#"
                    (scoped_identifier
                      path: (scoped_identifier
                        path: (identifier) @crate
                        name: (identifier) @module
                        (#eq? @crate "ring")
                        (#match? @module "digest|aead|signature")))
                "#.to_string(),
                language: ScanLanguage::Rust,
                match_type: AstMatchType::Library { name: "ring".to_string() },
                metadata: HashMap::new(),
            },
            
            // Python cryptography library imports
            AstPattern {
                query: r#"
                    (import_from_statement
                      module_name: (dotted_name) @name
                      (#match? @name "cryptography.*"))
                "#.to_string(),
                language: ScanLanguage::Python,
                match_type: AstMatchType::Library { name: "cryptography".to_string() },
                metadata: HashMap::new(),
            },
            
            // Python simple import statements
            AstPattern {
                query: r#"
                    (import_statement
                      name: (dotted_name) @name
                      (#match? @name "cryptography.*"))
                "#.to_string(),
                language: ScanLanguage::Python,
                match_type: AstMatchType::Library { name: "cryptography".to_string() },
                metadata: HashMap::new(),
            },
            
            // Python AES algorithm calls
            AstPattern {
                query: r#"
                    (call
                      function: (attribute
                        object: (identifier) @obj
                        attribute: (identifier) @attr
                        (#eq? @obj "algorithms")
                        (#eq? @attr "AES")))
                "#.to_string(),
                language: ScanLanguage::Python,
                match_type: AstMatchType::Algorithm { 
                    name: "AES".to_string(),
                    primitive: "aead".to_string(),
                    nist_quantum_security_level: 3,
                },
                metadata: HashMap::new(),
            },
            
            // Java crypto API imports
            AstPattern {
                query: r#"
                    (import_declaration
                      (scoped_identifier
                        scope: (scoped_identifier
                          scope: (identifier) @javax
                          name: (identifier) @crypto
                          (#eq? @javax "javax")
                          (#eq? @crypto "crypto"))))
                "#.to_string(),
                language: ScanLanguage::Java,
                match_type: AstMatchType::Library { name: "JCA".to_string() },
                metadata: HashMap::new(),
            },
            
            // Go crypto package imports
            AstPattern {
                query: r#"
                    (import_spec
                      path: (interpreted_string_literal) @path
                      (#match? @path "\"crypto/.*\""))
                "#.to_string(),
                language: ScanLanguage::Go,
                match_type: AstMatchType::Library { name: "std-crypto".to_string() },
                metadata: HashMap::new(),
            },
            
            // PHP OpenSSL function calls
            AstPattern {
                query: r#"
                    (function_call_expression
                      function: (name) @func
                      (#match? @func "openssl_.*"))
                "#.to_string(),
                language: ScanLanguage::Php,
                match_type: AstMatchType::Library { name: "OpenSSL".to_string() },
                metadata: HashMap::new(),
            },
            
            // Swift CryptoKit imports
            AstPattern {
                query: r#"
                    (import_declaration
                      (identifier) @name
                      (#eq? @name "CryptoKit"))
                "#.to_string(),
                language: ScanLanguage::Swift,
                match_type: AstMatchType::Library { name: "CryptoKit".to_string() },
                metadata: HashMap::new(),
            },
            
            // Kotlin JCA imports
            AstPattern {
                query: r#"
                    (import_header
                      (identifier) @javax
                      (identifier) @crypto
                      (#eq? @javax "javax")
                      (#eq? @crypto "crypto"))
                "#.to_string(),
                language: ScanLanguage::Kotlin,
                match_type: AstMatchType::Library { name: "JCA".to_string() },
                metadata: HashMap::new(),
            },
            
            // Objective-C CommonCrypto imports
            AstPattern {
                query: r#"
                    (preproc_include
                      path: (system_lib_string) @path
                      (#match? @path "CommonCrypto/.*"))
                "#.to_string(),
                language: ScanLanguage::ObjC,
                match_type: AstMatchType::Library { name: "CommonCrypto".to_string() },
                metadata: HashMap::new(),
            },
            
            
        ]
    }
    
    /// Parse source code and return the AST
    pub fn parse(&mut self, language: ScanLanguage, source: &[u8]) -> Result<Tree> {
        let parser = self.parsers.get_mut(&language)
            .ok_or_else(|| anyhow!("No parser available for language: {:?}", language))?;
            
        parser.parse(source, None)
            .ok_or_else(|| anyhow!("Failed to parse source code"))
    }
    
    /// Execute AST queries and find matches
    pub fn find_matches(&self, language: ScanLanguage, tree: &Tree, source: &[u8]) -> Result<Vec<AstMatch>> {
        let mut matches = Vec::new();
        
        // Get the tree-sitter language for query compilation
        let ts_language = match language {
            ScanLanguage::C => tree_sitter_c::language(),
            ScanLanguage::Cpp => tree_sitter_cpp::language(),
            ScanLanguage::Rust => tree_sitter_rust::language(),
            ScanLanguage::Python => tree_sitter_python::language(),
            ScanLanguage::Java => tree_sitter_java::language(),
            ScanLanguage::Go => tree_sitter_go::language(),
            _ => return Ok(matches), // Skip unsupported languages
        };
        
        // Execute each pattern that matches this language
        for pattern in &self.patterns {
            if pattern.language != language {
                continue;
            }
            
            // Compile and execute the query
            let query = Query::new(&ts_language, &pattern.query)
                .map_err(|e| anyhow!("Failed to compile query: {}", e))?;
                
            let mut cursor = QueryCursor::new();
            let query_matches = cursor.matches(&query, tree.root_node(), source);
            
            for query_match in query_matches {
                for capture in query_match.captures {
                    let node = capture.node;
                    let start_pos = node.start_position();
                    let end_pos = node.end_position();
                    
                    let text = node.utf8_text(source)
                        .unwrap_or("<invalid utf8>")
                        .to_string();
                    
                    matches.push(AstMatch {
                        match_type: pattern.match_type.clone(),
                        text,
                        start_line: start_pos.row + 1, // Convert to 1-based
                        start_column: start_pos.column + 1,
                        end_line: end_pos.row + 1,
                        end_column: end_pos.column + 1,
                        metadata: pattern.metadata.clone(),
                    });
                }
            }
        }
        
        Ok(matches)
    }
    
    /// Add custom patterns from configuration
    pub fn add_patterns(&mut self, patterns: Vec<AstPattern>) {
        self.patterns.extend(patterns);
    }
}

/// A match found by AST pattern matching
#[derive(Debug, Clone)]
pub struct AstMatch {
    pub match_type: AstMatchType,
    pub text: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub metadata: HashMap<String, String>,
}

/// AST-based detector that implements the Detector trait
pub struct AstBasedDetector {
    id: &'static str,
    languages: &'static [ScanLanguage],
    ast_detector: AstDetector,
}

impl AstBasedDetector {
    pub fn new(id: &'static str, languages: &'static [ScanLanguage]) -> Result<Self> {
        Ok(Self {
            id,
            languages,
            ast_detector: AstDetector::new()?,
        })
    }
    
    pub fn with_patterns(
        id: &'static str, 
        languages: &'static [ScanLanguage], 
        patterns: Vec<AstPattern>
    ) -> Result<Self> {
        let mut detector = Self::new(id, languages)?;
        detector.ast_detector.add_patterns(patterns);
        Ok(detector)
    }
}

impl crate::Detector for AstBasedDetector {
    fn id(&self) -> &'static str {
        self.id
    }
    
    fn languages(&self) -> &'static [ScanLanguage] {
        self.languages
    }
    
    fn prefilter(&self) -> crate::Prefilter {
        // For AST-based detection, we can use broader prefilters since AST parsing is more precise
        crate::Prefilter {
            extensions: std::collections::BTreeSet::new(), // Will be handled by language detection
            substrings: std::collections::BTreeSet::new(), // AST parsing doesn't need substring prefiltering
        }
    }
    
    fn scan(&self, unit: &ScanUnit, em: &mut Emitter) -> Result<()> {
        // Parse the source code into an AST
        let mut detector = AstDetector::new()?;
        let tree = detector.parse(unit.lang, &unit.bytes)?;
        
        // Find matches using AST queries
        let matches = detector.find_matches(unit.lang, &tree, &unit.bytes)?;
        
        // Convert AST matches to findings
        for ast_match in matches {
            let (library, symbol) = match &ast_match.match_type {
                AstMatchType::Library { name } => (name.clone(), ast_match.text.clone()),
                AstMatchType::Algorithm { name, .. } => ("crypto-lib".to_string(), name.clone()),
            };
            
            let finding = Finding {
                language: unit.lang,
                library,
                file: unit.path.clone(),
                span: Span {
                    line: ast_match.start_line,
                    column: ast_match.start_column,
                },
                symbol,
                snippet: ast_match.text,
                detector_id: self.id.to_string(),
            };
            
            em.send(finding)?;
        }
        
        Ok(())
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ast_detector_creation() {
        let detector = AstDetector::new();
        assert!(detector.is_ok());
    }
    
    #[test]
    fn test_c_parsing() {
        let mut detector = AstDetector::new().unwrap();
        let source = b"#include <openssl/rsa.h>\nint main() { return 0; }";
        let tree = detector.parse(ScanLanguage::C, source);
        assert!(tree.is_ok());
    }
    
    #[test]
    fn test_rust_parsing() {
        let mut detector = AstDetector::new().unwrap();
        let source = b"use crypto::digest::Digest;";
        let tree = detector.parse(ScanLanguage::Rust, source);
        assert!(tree.is_ok());
    }
}