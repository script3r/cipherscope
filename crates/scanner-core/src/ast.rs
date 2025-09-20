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
    /// Get default patterns (empty - all patterns should come from patterns.toml)
    fn default_patterns() -> Vec<AstPattern> {
        Vec::new() // No hardcoded patterns - everything comes from patterns.toml
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
    registry: std::sync::Arc<crate::PatternRegistry>,
}

impl AstBasedDetector {
    pub fn new(id: &'static str, languages: &'static [ScanLanguage], registry: std::sync::Arc<crate::PatternRegistry>) -> Result<Self> {
        Ok(Self {
            id,
            languages,
            ast_detector: AstDetector::new()?,
            registry,
        })
    }
    
    pub fn with_patterns(
        id: &'static str, 
        languages: &'static [ScanLanguage], 
        patterns: Vec<AstPattern>,
        registry: std::sync::Arc<crate::PatternRegistry>,
    ) -> Result<Self> {
        let mut detector = Self::new(id, languages, registry)?;
        detector.ast_detector.add_patterns(patterns);
        Ok(detector)
    }
}

impl AstBasedDetector {
    /// Check if library anchors (includes/imports) are present using AST
    fn check_library_anchors(&self, tree: &Tree, source: &[u8], language: ScanLanguage, library: &crate::LibrarySpec) -> Result<bool> {
        // Convert include patterns to AST queries
        for include_pattern in &library.patterns.include {
            if self.regex_to_ast_match(tree, source, language, include_pattern, "include")? {
                return Ok(true);
            }
        }
        
        // Convert import patterns to AST queries  
        for import_pattern in &library.patterns.import {
            if self.regex_to_ast_match(tree, source, language, import_pattern, "import")? {
                return Ok(true);
            }
        }
        
        // If no anchor patterns defined, consider it satisfied
        if library.patterns.include.is_empty() && library.patterns.import.is_empty() && library.patterns.namespace.is_empty() {
            return Ok(true);
        }
        
        Ok(false)
    }
    
    /// Find API usage patterns using AST
    fn find_api_usage(&self, tree: &Tree, source: &[u8], language: ScanLanguage, library: &crate::LibrarySpec, unit: &ScanUnit) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for api_pattern in &library.patterns.apis {
            let matches = self.regex_to_ast_findings(tree, source, language, api_pattern, "api", &library.name, unit)?;
            findings.extend(matches);
        }
        
        Ok(findings)
    }
    
    /// Find algorithm usage patterns using AST
    fn find_algorithm_usage(&self, tree: &Tree, source: &[u8], language: ScanLanguage, library: &crate::LibrarySpec, unit: &ScanUnit) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        for algorithm in &library.algorithms {
            for symbol_pattern in &algorithm.symbol_patterns {
                let matches = self.regex_to_ast_findings(tree, source, language, symbol_pattern, "algorithm", &algorithm.name, unit)?;
                findings.extend(matches);
            }
        }
        
        Ok(findings)
    }
    
    /// Convert a regex pattern to AST matching (simplified implementation)
    fn regex_to_ast_match(&self, tree: &Tree, source: &[u8], language: ScanLanguage, regex_pattern: &str, pattern_type: &str) -> Result<bool> {
        // Create a dummy unit for this check
        let dummy_unit = ScanUnit {
            path: std::path::PathBuf::from(""),
            lang: language,
            bytes: std::sync::Arc::from(&[] as &[u8]),
        };
        let findings = self.regex_to_ast_findings(tree, source, language, regex_pattern, pattern_type, "unknown", &dummy_unit)?;
        Ok(!findings.is_empty())
    }
    
    /// Convert regex pattern to AST findings (agnostic implementation)
    fn regex_to_ast_findings(&self, tree: &Tree, source: &[u8], language: ScanLanguage, regex_pattern: &str, pattern_type: &str, symbol_name: &str, unit: &ScanUnit) -> Result<Vec<Finding>> {
        // Get generic AST query for this language and pattern type
        let ast_query = self.convert_regex_to_ast_query(regex_pattern, language, pattern_type)?;
        
        if let Some(query_str) = ast_query {
            // Execute the generic AST query
            let ast_matches = self.execute_ast_query(tree, source, language, &query_str)?;
            
            // Filter AST matches using the regex pattern from patterns.toml
            let regex = regex::Regex::new(regex_pattern)
                .map_err(|e| anyhow!("Invalid regex pattern '{}': {}", regex_pattern, e))?;
            
            let findings = ast_matches.into_iter()
                .filter(|ast_match| regex.is_match(&ast_match.text))
                .map(|ast_match| {
                    Finding {
                        language,
                        library: symbol_name.to_string(),
                        file: unit.path.clone(),
                        span: Span {
                            line: ast_match.start_line,
                            column: ast_match.start_column,
                        },
                        symbol: ast_match.text.clone(),
                        snippet: ast_match.text,
                        detector_id: self.id.to_string(),
                    }
                }).collect();
            Ok(findings)
        } else {
            Ok(Vec::new())
        }
    }
    
    /// Convert regex pattern to generic AST query (completely agnostic)
    fn convert_regex_to_ast_query(&self, regex_pattern: &str, language: ScanLanguage, pattern_type: &str) -> Result<Option<String>> {
        // Create generic AST queries based on language and pattern type
        // The actual matching content comes from the regex pattern
        let result = match (language, pattern_type) {
            // C/C++ include statements (capture full include directive)
            (ScanLanguage::C | ScanLanguage::Cpp, "include") => {
                Some(r#"(preproc_include) @include"#.to_string())
            },
            // C/C++ function calls  
            (ScanLanguage::C | ScanLanguage::Cpp, "api") => {
                Some(r#"(call_expression function: (identifier) @func)"#.to_string())
            },
            // Python import statements (from X import Y) - capture full statement
            (ScanLanguage::Python, "include") if regex_pattern.contains("from\\s+") => {
                Some(r#"(import_from_statement) @import"#.to_string())
            },
            // Python import statements (import X) - capture full statement
            (ScanLanguage::Python, "include") if regex_pattern.contains("import\\s+") => {
                Some(r#"(import_statement) @import"#.to_string())
            },
            // Python API calls and object access
            (ScanLanguage::Python, "api") => {
                Some(r#"[(call function: (identifier) @func) (call function: (attribute object: (identifier) @obj attribute: (identifier) @attr)) (identifier) @id]"#.to_string())
            },
            // Java import statements - capture full statement
            (ScanLanguage::Java, "include") => {
                Some(r#"(import_declaration) @import"#.to_string())
            },
            // Java method calls and object access
            (ScanLanguage::Java, "api") => {
                Some(r#"[(method_invocation name: (identifier) @method) (identifier) @id]"#.to_string())
            },
            // Go import statements - capture full statement  
            (ScanLanguage::Go, "include") => {
                Some(r#"(import_spec) @import"#.to_string())
            },
            // Go function calls and object access
            (ScanLanguage::Go, "api") => {
                Some(r#"[(call_expression function: (identifier) @func) (selector_expression field: (field_identifier) @field)]"#.to_string())
            },
            // Rust use declarations - capture full statement
            (ScanLanguage::Rust, "include") => {
                Some(r#"(use_declaration) @use"#.to_string())
            },
            // Rust object access and method calls
            (ScanLanguage::Rust, "api") => {
                Some(r#"[(scoped_identifier) @scoped (call_expression function: (identifier) @func) (identifier) @id]"#.to_string())
            },
            _ => None, // Language not supported
        };
        Ok(result)
    }
    
    /// Execute an AST query and return matches, filtering by regex pattern
    fn execute_ast_query(&self, tree: &Tree, source: &[u8], language: ScanLanguage, query_str: &str) -> Result<Vec<AstMatch>> {
        // Get the tree-sitter language for query compilation
        let ts_language = match language {
            ScanLanguage::C => tree_sitter_c::language(),
            ScanLanguage::Cpp => tree_sitter_cpp::language(),
            ScanLanguage::Rust => tree_sitter_rust::language(),
            ScanLanguage::Python => tree_sitter_python::language(),
            ScanLanguage::Java => tree_sitter_java::language(),
            ScanLanguage::Go => tree_sitter_go::language(),
            _ => return Ok(Vec::new()), // Skip unsupported languages
        };
        
        // Compile and execute the query
        let query = Query::new(&ts_language, query_str)
            .map_err(|e| anyhow!("Failed to compile query '{}': {}", query_str, e))?;
            
        let mut cursor = QueryCursor::new();
        let query_matches = cursor.matches(&query, tree.root_node(), source);
        
        let mut matches = Vec::new();
        for query_match in query_matches {
            for capture in query_match.captures {
                let node = capture.node;
                let start_pos = node.start_position();
                let end_pos = node.end_position();
                
                let text = node.utf8_text(source)
                    .unwrap_or("<invalid utf8>")
                    .to_string();
                
                matches.push(AstMatch {
                    match_type: AstMatchType::Library { name: "generic".to_string() }, // Will be set by caller
                    text,
                    start_line: start_pos.row + 1, // Convert to 1-based
                    start_column: start_pos.column + 1,
                    end_line: end_pos.row + 1,
                    end_column: end_pos.column + 1,
                    metadata: HashMap::new(),
                });
            }
        }
        
        Ok(matches)
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
        let mut ast_detector = AstDetector::new()?;
        let tree = ast_detector.parse(unit.lang, &unit.bytes)?;
        
        // Get libraries for this language from the pattern registry
        let libraries = self.registry.libraries_for_language(unit.lang);
        
        for library in libraries {
            // Check library anchors (includes/imports/namespaces) using AST
            let has_library_anchor = self.check_library_anchors(&tree, &unit.bytes, unit.lang, library)?;
            
            if has_library_anchor {
                // Look for API usage patterns
                let api_findings = self.find_api_usage(&tree, &unit.bytes, unit.lang, library, unit)?;
                for finding in api_findings {
                    em.send(finding)?;
                }
                
                // Look for algorithm patterns
                let algo_findings = self.find_algorithm_usage(&tree, &unit.bytes, unit.lang, library, unit)?;
                for finding in algo_findings {
                    em.send(finding)?;
                }
            }
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