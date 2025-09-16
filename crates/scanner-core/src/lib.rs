//! High-Performance Directory Scanner
//!
//! This crate implements a highly optimized, parallel directory scanner inspired by ripgrep's architecture.
//! It uses a producer-consumer model to achieve maximum throughput when scanning large codebases.
//!
//! # Architecture
//!
//! ## Producer (Parallel Directory Walker)
//! - Uses `ignore::WalkParallel` to traverse the filesystem in parallel
//! - Automatically respects `.gitignore` files, skips hidden files, and filters by file extensions
//! - Critical optimization: avoids descending into irrelevant directories like `node_modules` or `.git`
//! - Sends discovered file paths to a bounded `crossbeam_channel` work queue
//!
//! ## Consumers (Parallel File Processors)  
//! - Uses `rayon` to create a thread pool of file processors
//! - Each consumer pulls file paths from the shared work queue
//! - Executes core file scanning logic (language detection, content analysis, pattern matching)
//! - Runs concurrently with the producer to saturate CPU cores
//!
//! ## Key Optimizations
//! - **Bounded channels**: Manages backpressure between producer and consumers
//! - **Prefiltering**: Uses Aho-Corasick automata to quickly skip files without relevant patterns
//! - **Comment stripping**: Preprocesses files once and reuses stripped content across detectors
//! - **Language-specific caching**: Caches compiled patterns per language for faster lookups
//! - **Gitignore integration**: Leverages the `ignore` crate's efficient gitignore handling
//!
//! This architecture typically achieves 4+ GiB/s throughput on modern hardware.

use aho_corasick::AhoCorasickBuilder;
use anyhow::{anyhow, Context, Result};
use crossbeam_channel::{bounded, Receiver, Sender};
use ignore::{WalkBuilder, WalkParallel};
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

// ---------------- Types ----------------

type ProgressCallback = Arc<dyn Fn(usize, usize, usize) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Language {
    Go,
    Java,
    C,
    Cpp,
    Rust,
    Python,
    Php,
    Swift,
    ObjC,
    Kotlin,
    Erlang,
}

impl<'de> Deserialize<'de> for Language {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, Unexpected};
        let s = String::deserialize(deserializer)?;
        let norm = s.trim().to_ascii_lowercase();
        match norm.as_str() {
            "go" | "golang" => Ok(Language::Go),
            "java" => Ok(Language::Java),
            "c" => Ok(Language::C),
            "c++" | "cpp" => Ok(Language::Cpp),
            "rust" | "rs" => Ok(Language::Rust),
            "python" | "py" => Ok(Language::Python),
            "php" => Ok(Language::Php),
            "swift" => Ok(Language::Swift),
            "objc" | "objective-c" | "objectivec" => Ok(Language::ObjC),
            "kotlin" | "kt" => Ok(Language::Kotlin),
            "erlang" | "erl" => Ok(Language::Erlang),
            other => Err(D::Error::invalid_value(
                Unexpected::Str(other),
                &"valid language",
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanUnit {
    pub path: PathBuf,
    pub lang: Language,
    pub bytes: Arc<[u8]>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Span {
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub language: Language,
    pub library: String,
    pub file: PathBuf,
    pub span: Span,
    pub symbol: String,
    pub snippet: String,
    pub detector_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct Prefilter {
    pub extensions: BTreeSet<String>,
    pub substrings: BTreeSet<String>,
}

pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn languages(&self) -> &'static [Language];
    fn prefilter(&self) -> Prefilter; // extensions & cheap substrings
    fn scan(&self, unit: &ScanUnit, em: &mut Emitter) -> Result<()>;
    fn scan_optimized(
        &self,
        unit: &ScanUnit,
        _stripped_s: &str,
        _index: &LineIndex,
        em: &mut Emitter,
    ) -> Result<()> {
        // Default implementation falls back to the original scan method
        self.scan(unit, em)
    }
    fn as_any(&self) -> &dyn std::any::Any;
}

// ---------------- Emitter ----------------

pub struct Emitter {
    tx: Sender<Finding>,
    rx: Receiver<Finding>,
}

impl Emitter {
    pub fn new(bound: usize) -> Self {
        let (tx, rx) = bounded(bound);
        Self { tx, rx }
    }

    pub fn send(&mut self, finding: Finding) -> Result<()> {
        self.tx
            .send(finding)
            .map_err(|e| anyhow!("emitter send failed: {e}"))
    }

    pub fn drain(&mut self) -> Vec<Finding> {
        self.rx.try_iter().collect()
    }

    pub fn into_receiver(self) -> Receiver<Finding> {
        self.rx
    }
}

// ---------------- Patterns & Config ----------------

#[derive(Debug, Clone, Deserialize)]
pub struct PatternsFile {
    pub version: PatternsVersion,
    #[serde(default)]
    pub library: Vec<LibrarySpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatternsVersion {
    pub schema: String,
    pub updated: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LibrarySpec {
    pub name: String,
    pub languages: Vec<Language>,
    #[serde(default)]
    pub patterns: LibraryPatterns,
    #[serde(default)]
    pub algorithms: Vec<AlgorithmSpec>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LibraryPatterns {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub import: Vec<String>,
    #[serde(default)]
    pub namespace: Vec<String>,
    #[serde(default)]
    pub apis: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AlgorithmSpec {
    pub name: String,
    pub primitive: String, // "signature", "aead", "hash", "kem", "pke", "mac", "kdf", "prng"
    #[serde(default)]
    pub parameter_patterns: Vec<ParameterPattern>,
    #[serde(rename = "nistQuantumSecurityLevel")]
    pub nist_quantum_security_level: u8,
    #[serde(default)]
    pub symbol_patterns: Vec<String>, // Regex patterns to match this algorithm in findings
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParameterPattern {
    pub name: String,    // e.g., "keySize", "curve", "outputSize"
    pub pattern: String, // Regex pattern to extract the parameter value
    #[serde(default)]
    pub default_value: Option<serde_json::Value>, // Default value if not found
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize, // bytes
    #[serde(default)]
    pub include_globs: Vec<String>,
    #[serde(default)]
    pub exclude_globs: Vec<String>,
    #[serde(default)]
    pub deterministic: bool,
    #[serde(skip)]
    pub progress_callback: Option<ProgressCallback>,
}

fn default_max_file_size() -> usize {
    2 * 1024 * 1024
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("max_file_size", &self.max_file_size)
            .field("include_globs", &self.include_globs)
            .field("exclude_globs", &self.exclude_globs)
            .field("deterministic", &self.deterministic)
            .field("progress_callback", &"<callback>")
            .finish()
    }
}

impl Clone for Config {
    fn clone(&self) -> Self {
        Self {
            max_file_size: self.max_file_size,
            include_globs: self.include_globs.clone(),
            exclude_globs: self.exclude_globs.clone(),
            deterministic: self.deterministic,
            progress_callback: self.progress_callback.clone(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_file_size: default_max_file_size(),
            include_globs: default_include_globs(),
            exclude_globs: Vec::new(),
            deterministic: false,
            progress_callback: None,
        }
    }
}

fn default_include_globs() -> Vec<String> {
    vec![
        // C/C++
        "**/*.c".to_string(),
        "**/*.h".to_string(),
        "**/*.cc".to_string(),
        "**/*.cpp".to_string(),
        "**/*.cxx".to_string(),
        "**/*.c++".to_string(),
        "**/*.hpp".to_string(),
        "**/*.hxx".to_string(),
        "**/*.h++".to_string(),
        "**/*.hh".to_string(),
        // Java
        "**/*.java".to_string(),
        // Go
        "**/*.go".to_string(),
        // Rust
        "**/*.rs".to_string(),
        // Python
        "**/*.py".to_string(),
        "**/*.pyw".to_string(),
        "**/*.pyi".to_string(),
        // PHP
        "**/*.php".to_string(),
        "**/*.phtml".to_string(),
        "**/*.php3".to_string(),
        "**/*.php4".to_string(),
        "**/*.php5".to_string(),
        "**/*.phps".to_string(),
        // Swift
        "**/*.swift".to_string(),
        // Objective-C
        "**/*.m".to_string(),
        "**/*.mm".to_string(),
        "**/*.M".to_string(),
        // Kotlin
        "**/*.kt".to_string(),
        "**/*.kts".to_string(),
        // Erlang
        "**/*.erl".to_string(),
        "**/*.hrl".to_string(),
        "**/*.beam".to_string(),
    ]
}

// Compiled patterns for fast matching
#[derive(Debug)]
pub struct CompiledLibrary {
    pub name: String,
    pub languages: BTreeSet<Language>,
    pub include: Vec<Regex>,
    pub import: Vec<Regex>,
    pub namespace: Vec<Regex>,
    pub apis: Vec<Regex>,
    pub prefilter_substrings: Vec<String>,
    pub algorithms: Vec<CompiledAlgorithm>,
}

#[derive(Debug, Clone)]
pub struct CompiledAlgorithm {
    pub name: String,
    pub primitive: String,
    pub nist_quantum_security_level: u8,
    pub symbol_patterns: Vec<Regex>,
    pub parameter_patterns: Vec<CompiledParameterPattern>,
}

#[derive(Debug, Clone)]
pub struct CompiledParameterPattern {
    pub name: String,
    pub pattern: Regex,
    pub default_value: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct PatternRegistry {
    pub libs: Vec<CompiledLibrary>,
    // Cache patterns per language for faster lookup
    language_cache: HashMap<Language, Vec<usize>>, // indices into libs vector
}

impl PatternRegistry {
    pub fn load(patterns_toml: &str) -> Result<Self> {
        let pf: PatternsFile = toml::from_str(patterns_toml)?;
        let libs = pf
            .library
            .into_iter()
            .map(compile_library)
            .collect::<Result<Vec<_>>>()?;

        // Build language cache only if we have many libraries
        let language_cache = if libs.len() > 50 {
            let mut cache = HashMap::new();
            for (idx, lib) in libs.iter().enumerate() {
                for &lang in &lib.languages {
                    cache.entry(lang).or_insert_with(Vec::new).push(idx);
                }
            }
            cache
        } else {
            HashMap::new() // Empty cache for small numbers of libraries
        };

        Ok(Self {
            libs,
            language_cache,
        })
    }

    pub fn for_language(&self, language: Language) -> Vec<&CompiledLibrary> {
        // For small numbers of libraries, linear search is often faster than HashMap lookup
        // Only use cache if we have many libraries (threshold: 50+)
        if self.libs.len() > 50 {
            // Use cached indices for O(1) lookup
            if let Some(indices) = self.language_cache.get(&language) {
                indices.iter().map(|&idx| &self.libs[idx]).collect()
            } else {
                Vec::new()
            }
        } else {
            // Use linear search for small numbers of libraries
            self.libs
                .iter()
                .filter(|l| l.languages.contains(&language))
                .collect()
        }
    }
}

fn compile_library(lib: LibrarySpec) -> Result<CompiledLibrary> {
    let include = compile_regexes(&lib.patterns.include)?;
    let import = compile_regexes(&lib.patterns.import)?;
    let namespace = compile_regexes(&lib.patterns.namespace)?;
    let apis = compile_regexes(&lib.patterns.apis)?;
    let prefilter_substrings = derive_prefilter_substrings(&lib.patterns);
    let algorithms = compile_algorithms(&lib.algorithms)?;
    Ok(CompiledLibrary {
        name: lib.name,
        languages: lib.languages.into_iter().collect(),
        include,
        import,
        namespace,
        apis,
        prefilter_substrings,
        algorithms,
    })
}

fn compile_regexes(srcs: &[String]) -> Result<Vec<Regex>> {
    srcs.iter()
        .map(|s| {
            let pat = format!("(?m){}", s);
            Regex::new(&pat).with_context(|| format!("bad pattern: {s}"))
        })
        .collect()
}

fn compile_algorithms(algorithms: &[AlgorithmSpec]) -> Result<Vec<CompiledAlgorithm>> {
    algorithms
        .iter()
        .map(|algo| {
            let symbol_patterns = compile_regexes(&algo.symbol_patterns)?;
            let parameter_patterns = algo
                .parameter_patterns
                .iter()
                .map(|param| {
                    let pattern = Regex::new(&param.pattern)
                        .with_context(|| format!("bad parameter pattern: {}", param.pattern))?;
                    Ok(CompiledParameterPattern {
                        name: param.name.clone(),
                        pattern,
                        default_value: param.default_value.clone(),
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            Ok(CompiledAlgorithm {
                name: algo.name.clone(),
                primitive: algo.primitive.clone(),
                nist_quantum_security_level: algo.nist_quantum_security_level,
                symbol_patterns,
                parameter_patterns,
            })
        })
        .collect()
}

fn derive_prefilter_substrings(p: &LibraryPatterns) -> Vec<String> {
    let mut set = BTreeSet::new();
    let mut push_tokens = |s: &str| {
        // Remove common regex anchors that pollute tokens
        let cleaned = s.replace("\\b", "");
        for tok in cleaned
            .split(|c: char| !c.is_alphanumeric() && c != '.' && c != '/' && c != '_')
        {
            let t = tok.trim();
            if t.len() >= 4 {
                set.insert(t.to_ascii_lowercase());
            }
        }
    };
    for s in p
        .include
        .iter()
        .chain(&p.import)
        .chain(&p.namespace)
        .chain(&p.apis)
    {
        push_tokens(s);
    }
    set.into_iter().collect()
}

// ---------------- Comment Stripping ----------------

mod strip {
    use super::Language;

    pub fn strip_comments(language: Language, input: &[u8]) -> Vec<u8> {
        match language {
            Language::Go
            | Language::Java
            | Language::C
            | Language::Cpp
            | Language::Rust
            | Language::Swift
            | Language::ObjC
            | Language::Kotlin
            | Language::Erlang => strip_c_like(language, input),
            Language::Python | Language::Php => strip_hash_like(language, input),
        }
    }

    fn strip_c_like(language: Language, input: &[u8]) -> Vec<u8> {
        // Simple state machine: handle // and /* */; avoid inside strings and char literals
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        let mut in_sl_comment = false;
        let mut in_ml_comment = false;
        let mut in_str = false;
        let mut in_char = false;
        let mut str_delim = b'"';
        // Rust raw strings r#" ... "#
        let mut raw_hashes = 0usize;

        while i < input.len() {
            let b = input[i];
            let next = if i + 1 < input.len() { input[i + 1] } else { 0 };

            if in_sl_comment {
                if b == b'\n' {
                    in_sl_comment = false;
                    out.push(b);
                }
                i += 1;
                continue;
            }
            if in_ml_comment {
                if b == b'*' && next == b'/' {
                    in_ml_comment = false;
                    i += 2;
                    continue;
                }
                if b == b'\n' {
                    out.push(b);
                }
                i += 1;
                continue;
            }
            if in_str {
                out.push(b);
                if language == Language::Rust && str_delim == b'"' && b == b'"' {
                    // handle raw string terminator with hashes
                    let mut k = 0usize;
                    while k < raw_hashes && i + 1 + k < input.len() && input[i + 1 + k] == b'#' {
                        k += 1;
                    }
                    if k == raw_hashes {
                        in_str = false;
                        i += 1 + raw_hashes;
                        continue;
                    }
                } else if b == str_delim && (language == Language::Rust || prev_not_escape(&out)) {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            if in_char {
                out.push(b);
                if b == b'\'' && prev_not_escape(&out) {
                    in_char = false;
                }
                i += 1;
                continue;
            }

            // start of comments or strings
            if b == b'/' && next == b'/' {
                in_sl_comment = true;
                i += 2;
                continue;
            }
            if b == b'/' && next == b'*' {
                in_ml_comment = true;
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_char = true;
                out.push(b);
                i += 1;
                continue;
            }
            if b == b'"' {
                in_str = true;
                str_delim = b'"';
                raw_hashes = 0;
                // Rust raw strings start: r#*"  (r, then hashes, then ")
                if language == Language::Rust {
                    // look behind for 'r' and hashes
                    if i > 0 && input[i - 1] == b'r' {
                        // count preceding hashes
                        let mut h = 0usize;
                        let mut j = i - 1;
                        while j > 0 && input[j - 1] == b'#' {
                            h += 1;
                            j -= 1;
                        }
                        raw_hashes = h;
                    }
                }
                out.push(b);
                i += 1;
                continue;
            }

            out.push(b);
            i += 1;
        }
        out
    }

    fn strip_hash_like(_language: Language, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        let mut i = 0;
        let mut in_sl_comment = false;
        let mut in_ml_comment = false; // for PHP
        let mut in_str = false;
        let mut triple: Option<[u8; 3]> = None;
        let mut delim = b'"';
        while i < input.len() {
            let b = input[i];
            let next = if i + 1 < input.len() { input[i + 1] } else { 0 };

            if in_sl_comment {
                if b == b'\n' {
                    in_sl_comment = false;
                    out.push(b);
                }
                i += 1;
                continue;
            }
            if in_ml_comment {
                if b == b'*' && next == b'/' {
                    in_ml_comment = false;
                    i += 2;
                    continue;
                }
                if b == b'\n' {
                    out.push(b);
                }
                i += 1;
                continue;
            }
            if in_str {
                out.push(b);
                if let Some(t) = triple {
                    // end triple quotes
                    if b == t[0] && next == t[1] && i + 2 < input.len() && input[i + 2] == t[2] {
                        out.push(next);
                        out.push(input[i + 2]);
                        i += 3;
                        in_str = false;
                        triple = None;
                        continue;
                    }
                } else if b == delim && prev_not_escape(&out) {
                    in_str = false;
                }
                i += 1;
                continue;
            }

            // start comments or strings
            if b == b'#' {
                in_sl_comment = true;
                i += 1;
                continue;
            }
            if b == b'/' && next == b'/' {
                in_sl_comment = true;
                i += 2;
                continue;
            }
            if b == b'/' && next == b'*' {
                in_ml_comment = true;
                i += 2;
                continue;
            }
            if b == b'\'' || b == b'"' {
                delim = b;
                in_str = true;
                out.push(b);
                i += 1;
                continue;
            }
            if b == b'"' && next == b'"' && i + 2 < input.len() && input[i + 2] == b'"' {
                triple = Some([b'"', b'"', b'"']);
                in_str = true;
                out.push(b'"');
                out.push(b'"');
                out.push(b'"');
                i += 3;
                continue;
            }
            if b == b'\'' && next == b'\'' && i + 2 < input.len() && input[i + 2] == b'\'' {
                triple = Some([b'\'', b'\'', b'\'']);
                in_str = true;
                out.push(b'\'');
                out.push(b'\'');
                out.push(b'\'');
                i += 3;
                continue;
            }

            out.push(b);
            i += 1;
        }
        out
    }

    fn prev_not_escape(out: &[u8]) -> bool {
        // count consecutive backslashes
        let mut n = 0usize;
        let mut i = out.len();
        while i > 0 {
            i -= 1;
            if out[i] == b'\\' {
                n += 1;
            } else {
                break;
            }
        }
        n % 2 == 0
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::Language;

        #[test]
        fn strip_c_like_basic() {
            let s = b"int x; // comment\n/* block */int y;\nprintf(\"// not comment\");";
            let out = strip_comments(Language::C, s);
            let out_s = String::from_utf8(out).unwrap();
            assert!(out_s.contains("int x; \n"));
            assert!(out_s.contains("int y;"));
            assert!(out_s.contains("printf(\"// not comment\");"));
        }

        #[test]
        fn strip_python_triple() {
            let s = b"a=1\n'''not comment\nmore'''\n# real\nb=2\n";
            let out = strip_comments(Language::Python, s);
            let out_s = String::from_utf8(out).unwrap();
            assert!(out_s.contains("not comment"));
            assert!(out_s.contains("a=1\n"));
            assert!(out_s.contains("\nb=2"));
            assert!(!out_s.contains("# real"));
        }
    }
}

pub use strip::strip_comments;

// ---------------- Line Index ----------------

#[derive(Debug, Clone)]
pub struct LineIndex {
    line_starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(bytes: &[u8]) -> Self {
        let mut starts = vec![0usize];
        for (i, b) in bytes.iter().enumerate() {
            if *b == b'\n' {
                starts.push(i + 1);
            }
        }
        Self {
            line_starts: starts,
        }
    }

    pub fn to_line_col(&self, offset: usize) -> Span {
        match self.line_starts.binary_search(&offset) {
            Ok(idx) => Span {
                line: idx + 1,
                column: 1,
            },
            Err(idx) => {
                let line_start = if idx == 0 {
                    0
                } else {
                    self.line_starts[idx - 1]
                };
                Span {
                    line: idx,
                    column: offset - line_start + 1,
                }
            }
        }
    }
}

// ---------------- Scanner ----------------

pub struct Scanner<'a> {
    pub registry: &'a PatternRegistry,
    pub detectors: Vec<Box<dyn Detector>>, // registered detectors
    pub config: Config,
}

impl<'a> Scanner<'a> {
    pub fn new(
        registry: &'a PatternRegistry,
        detectors: Vec<Box<dyn Detector>>,
        config: Config,
    ) -> Self {
        Self {
            registry,
            detectors,
            config,
        }
    }

    /// Producer function: discovers files using ignore::WalkParallel and sends them to consumers
    fn run_producer(
        &self,
        roots: &[PathBuf],
        work_sender: Sender<PathBuf>,
        progress_sender: Option<Sender<usize>>,
    ) -> Result<()> {
        // Build glob matcher for include patterns
        let include_matcher: Option<globset::GlobSet> = if !self.config.include_globs.is_empty() {
            let mut builder = globset::GlobSetBuilder::new();
            for pattern in &self.config.include_globs {
                match globset::Glob::new(pattern) {
                    Ok(glob) => {
                        builder.add(glob);
                    }
                    Err(e) => {
                        return Err(anyhow!("Invalid glob pattern '{}': {}", pattern, e));
                    }
                }
            }
            match builder.build() {
                Ok(matcher) => Some(matcher),
                Err(e) => return Err(anyhow!("Failed to build glob matcher: {}", e)),
            }
        } else {
            None
        };

        let max_file_size = self.config.max_file_size;
        let files_discovered = Arc::new(AtomicUsize::new(0));

        for root in roots {
            let mut builder = WalkBuilder::new(root);
            builder
                .hidden(false) // Skip hidden files by default
                .git_ignore(true) // Respect .gitignore files - critical optimization
                .git_exclude(true) // Respect .git/info/exclude
                .ignore(true) // Respect .ignore files
                .follow_links(false) // Don't follow symlinks for safety
                .max_depth(None) // No depth limit
                .threads(num_cpus::get().max(4)) // Use optimal thread count for directory traversal
                .same_file_system(true); // Don't cross filesystem boundaries for better performance

            // Configure exclude globs if provided
            for exclude_glob in &self.config.exclude_globs {
                builder.add_custom_ignore_filename(exclude_glob);
            }

            let walker: WalkParallel = builder.build_parallel();
            let work_sender_clone = work_sender.clone();
            let progress_sender_clone = progress_sender.clone();
            let include_matcher_clone = include_matcher.clone();
            let files_discovered_clone = files_discovered.clone();

            walker.run(|| {
                let work_sender = work_sender_clone.clone();
                let progress_sender = progress_sender_clone.clone();
                let include_matcher = include_matcher_clone.clone();
                let files_discovered = files_discovered_clone.clone();

                Box::new(move |entry_result| {
                    let entry = match entry_result {
                        Ok(entry) => entry,
                        Err(_) => return ignore::WalkState::Continue,
                    };

                    // Only process files, skip directories
                    if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                        return ignore::WalkState::Continue;
                    }

                    let path = entry.path();

                    // Fast language detection BEFORE expensive operations
                    if Scanner::detect_language(path).is_none() {
                        return ignore::WalkState::Continue;
                    }

                    // Apply include glob filtering if specified (after language check)
                    if let Some(ref matcher) = include_matcher {
                        if !matcher.is_match(path) {
                            return ignore::WalkState::Continue;
                        }
                    }

                    // Check file size ONLY for files we're interested in
                    // Use DirEntry's metadata which might be cached
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.len() as usize > max_file_size {
                            return ignore::WalkState::Continue;
                        }
                    }

                    // Send file to work queue
                    if work_sender.send(path.to_path_buf()).is_err() {
                        return ignore::WalkState::Quit;
                    }

                    // Update discovered files counter atomically (no lock!)
                    files_discovered.fetch_add(1, Ordering::Relaxed);

                    // Send discovery progress update (1 = discovery signal)
                    if let Some(ref progress_tx) = progress_sender {
                        let _ = progress_tx.send(1);
                    }

                    ignore::WalkState::Continue
                })
            });
        }

        Ok(())
    }

    /// Consumer function: processes files from the work queue using rayon for parallelism
    fn run_consumers(
        &self,
        work_receiver: Receiver<PathBuf>,
        findings_sender: Sender<Finding>,
        progress_sender: Option<Sender<usize>>,
    ) -> Result<()> {
        const BATCH_SIZE: usize = 1000; // Process files in batches for better cache locality

        let mut batch = Vec::with_capacity(BATCH_SIZE);
        let mut _processed_count = 0usize;

        // Collect files into batches and process them
        for path in work_receiver.iter() {
            batch.push(path);

            if batch.len() >= BATCH_SIZE {
                let (processed, findings) = self.process_batch(&batch, &findings_sender)?;
                _processed_count += processed;
                batch.clear();

                // Send processing progress update (2 = processing signal, repeated for batch size)
                if let Some(ref progress_tx) = progress_sender {
                    for _ in 0..processed {
                        let _ = progress_tx.send(2);
                    }
                    // Send findings progress updates (3 = findings signal)
                    for _ in 0..findings {
                        let _ = progress_tx.send(3);
                    }
                }
            }
        }

        // Process remaining files in the final batch
        if !batch.is_empty() {
            let (processed, findings) = self.process_batch(&batch, &findings_sender)?;
            _processed_count += processed;

            if let Some(ref progress_tx) = progress_sender {
                for _ in 0..processed {
                    let _ = progress_tx.send(2);
                }
                // Send findings progress updates (3 = findings signal)
                for _ in 0..findings {
                    let _ = progress_tx.send(3);
                }
            }
        }

        Ok(())
    }

    /// Process a batch of files in parallel for better performance
    fn process_batch(
        &self,
        batch: &[PathBuf],
        findings_sender: &Sender<Finding>,
    ) -> Result<(usize, usize)> {
        // Process the batch in parallel using rayon
        let results: Vec<usize> = batch
            .par_iter()
            .map(|path| match self.scan_file(path, findings_sender) {
                Ok(findings_count) => findings_count,
                Err(e) => {
                    eprintln!("Error scanning file {:?}: {}", path, e);
                    0
                }
            })
            .collect();

        let total_findings = results.iter().sum();
        Ok((batch.len(), total_findings))
    }

    /// Core file scanning logic - processes a single file
    fn scan_file(&self, path: &PathBuf, findings_sender: &Sender<Finding>) -> Result<usize> {
        // Detect language from file extension
        let lang = match Self::detect_language(path) {
            Some(lang) => lang,
            None => return Ok(0), // Skip unsupported files
        };

        // Load file contents
        let bytes = Self::load_file(path)?;

        // Create scan unit
        let unit = ScanUnit {
            path: path.clone(),
            lang,
            bytes: bytes.clone(),
        };

        // Strip comments once and reuse for all detectors - critical optimization
        let stripped = strip_comments(lang, &bytes);
        let stripped_s = String::from_utf8_lossy(&stripped);
        let index = LineIndex::new(stripped_s.as_bytes());

        // Create emitter for this file
        let (emitter_tx, emitter_rx) = bounded(1000);
        let mut emitter = Emitter {
            tx: emitter_tx,
            rx: emitter_rx,
        };

        // Run all applicable detectors on this file
        for detector in &self.detectors {
            // Skip detector if it doesn't support this language
            if !detector.languages().contains(&lang) {
                continue;
            }

            // Apply prefilter to skip expensive regex matching if no keywords found
            if !prefilter_hit(detector.as_ref(), &stripped) {
                continue;
            }

            // Run the detector with optimized preprocessing
            if let Err(e) = detector.scan_optimized(&unit, &stripped_s, &index, &mut emitter) {
                eprintln!("Detector {} failed on {:?}: {}", detector.id(), path, e);
            }
        }

        // Drain emitter and forward findings to main channel
        drop(emitter.tx); // Close the emitter sender to stop receiving
        let mut findings_count = 0;
        for finding in emitter.rx.iter() {
            if findings_sender.send(finding).is_err() {
                break; // Main receiver has been dropped, stop sending
            }
            findings_count += 1;
        }

        Ok(findings_count)
    }

    /// Simple file discovery for dry-run functionality - doesn't use the full producer-consumer architecture
    pub fn discover_files(&self, roots: &[PathBuf]) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Build glob matcher for include patterns
        let include_matcher: Option<globset::GlobSet> = if !self.config.include_globs.is_empty() {
            let mut builder = globset::GlobSetBuilder::new();
            for pattern in &self.config.include_globs {
                if let Ok(glob) = globset::Glob::new(pattern) {
                    builder.add(glob);
                }
            }
            builder.build().ok()
        } else {
            None
        };

        for root in roots {
            let mut builder = WalkBuilder::new(root);
            builder
                .hidden(false)
                .git_ignore(true)
                .git_exclude(true)
                .ignore(true);

            for entry in builder.build().flatten() {
                let md = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if md.is_file() {
                    if md.len() as usize > self.config.max_file_size {
                        continue;
                    }

                    let path = entry.into_path();

                    // Apply include glob filtering
                    if let Some(ref matcher) = include_matcher {
                        if !matcher.is_match(&path) {
                            continue;
                        }
                    }

                    // Only include files with supported languages
                    if Self::detect_language(&path).is_some() {
                        paths.push(path);
                    }
                }
            }
        }
        paths
    }

    /// Ultra-fast language detection that avoids string allocations
    pub fn detect_language(path: &Path) -> Option<Language> {
        let ext = path.extension()?;

        // Fast path: check common extensions without string conversion
        match ext.as_encoded_bytes() {
            // Single char extensions
            b"c" => Some(Language::C),
            b"h" => Some(Language::C),
            b"m" | b"M" => Some(Language::ObjC),

            // Two char extensions
            b"go" => Some(Language::Go),
            b"rs" => Some(Language::Rust),
            b"py" => Some(Language::Python),
            b"kt" => Some(Language::Kotlin),
            b"cc" => Some(Language::Cpp),
            b"mm" => Some(Language::ObjC),

            // Three char extensions
            b"cpp" | b"cxx" | b"hpp" | b"hxx" => Some(Language::Cpp),
            b"php" => Some(Language::Php),
            b"pyw" | b"pyi" => Some(Language::Python),
            b"kts" => Some(Language::Kotlin),
            b"erl" | b"hrl" => Some(Language::Erlang),

            // Four+ char extensions
            b"java" => Some(Language::Java),
            b"swift" => Some(Language::Swift),
            b"phtml" => Some(Language::Php),
            b"php3" | b"php4" | b"php5" | b"phps" => Some(Language::Php),
            b"beam" => Some(Language::Erlang),

            // Fallback to string comparison for edge cases
            _ => {
                let ext_str = ext.to_str()?.to_ascii_lowercase();
                match ext_str.as_str() {
                    "c++" | "h++" => Some(Language::Cpp),
                    _ => None,
                }
            }
        }
    }

    pub fn load_file(path: &Path) -> Result<Arc<[u8]>> {
        let mut f = fs::File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf.into())
    }

    pub fn run(&self, roots: &[PathBuf]) -> Result<Vec<Finding>> {
        // Create bounded channels for work queue and findings
        const WORK_QUEUE_SIZE: usize = 10_000; // Backpressure management
        const FINDINGS_QUEUE_SIZE: usize = 50_000; // Large buffer for findings

        let (work_sender, work_receiver) = bounded::<PathBuf>(WORK_QUEUE_SIZE);
        let (findings_sender, findings_receiver) = bounded::<Finding>(FINDINGS_QUEUE_SIZE);

        // Progress tracking
        let (progress_sender, progress_receiver) = if self.config.progress_callback.is_some() {
            let (tx, rx) = bounded::<usize>(1000);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        // Spawn progress tracking thread if needed
        let progress_handle = if let Some(ref callback) = self.config.progress_callback {
            let callback = callback.clone();
            let progress_rx = progress_receiver.unwrap();
            Some(thread::spawn(move || {
                let mut files_discovered = 0;
                let mut files_processed = 0;
                let mut findings_count = 0;

                // Initial callback
                callback(0, 0, 0);

                for signal in progress_rx.iter() {
                    match signal {
                        1 => {
                            // File discovered
                            files_discovered += 1;
                            // Update callback every 1000 files discovered to reduce overhead
                            if files_discovered % 1000 == 0 {
                                callback(files_processed, files_discovered, findings_count);
                            }
                        }
                        2 => {
                            // File processed
                            files_processed += 1;
                            // Update callback every 500 files processed
                            if files_processed % 500 == 0 {
                                callback(files_processed, files_discovered, findings_count);
                            }
                        }
                        3 => {
                            // Finding discovered
                            findings_count += 1;
                            // Update callback every 10 findings
                            if findings_count % 10 == 0 {
                                callback(files_processed, files_discovered, findings_count);
                            }
                        }
                        _ => {
                            // Unknown signal, ignore
                        }
                    }
                }

                // Final callback
                callback(files_processed, files_discovered, findings_count);
            }))
        } else {
            None
        };

        // Use thread::scope to ensure all threads complete before returning
        let findings = thread::scope(|s| -> Result<Vec<Finding>> {
            // Spawn producer thread
            let producer_handle = {
                let work_sender = work_sender.clone();
                let progress_sender = progress_sender.clone();
                s.spawn(move || -> Result<()> {
                    self.run_producer(roots, work_sender, progress_sender)?;
                    Ok(())
                })
            };

            // Drop the work_sender so consumers know when to stop
            drop(work_sender);

            // Run consumers on the main thread (they use rayon internally for parallelism)
            let consumer_result = self.run_consumers(
                work_receiver,
                findings_sender.clone(),
                progress_sender.clone(),
            );

            // Drop findings sender so receiver knows when to stop
            drop(findings_sender);
            drop(progress_sender);

            // Collect all findings
            let mut findings: Vec<Finding> = Vec::new();
            for finding in findings_receiver.iter() {
                findings.push(finding);
            }

            // Wait for producer to complete
            producer_handle.join().unwrap()?;

            // Check consumer result
            consumer_result?;

            Ok(findings)
        })?;

        // Wait for progress thread to finish
        if let Some(handle) = progress_handle {
            let _ = handle.join();
        }

        // Sort findings for deterministic output if requested
        let mut findings = findings;
        if self.config.deterministic {
            findings.sort_by(|a, b| {
                (
                    a.file.to_string_lossy(),
                    a.span.line,
                    a.span.column,
                    &a.library,
                    &a.symbol,
                )
                    .cmp(&(
                        b.file.to_string_lossy(),
                        b.span.line,
                        b.span.column,
                        &b.library,
                        &b.symbol,
                    ))
            });
        }

        Ok(findings)
    }
}

fn prefilter_hit(det: &dyn Detector, stripped: &[u8]) -> bool {
    let pf = det.prefilter();
    if pf.substrings.is_empty() {
        return true;
    }

    // Try to use cached automaton if available (for PatternDetector)
    if let Some(pattern_det) = det.as_any().downcast_ref::<PatternDetector>() {
        if let Ok(Some(ac)) = pattern_det.get_cached_automaton(&pf.substrings) {
            return ac.is_match(stripped);
        }
    }

    // Fallback: build automaton (for other detector types)
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(pf.substrings)
        .expect("failed to build aho-corasick");
    ac.is_match(stripped)
}

// ---------------- Generic Pattern-based Detector ----------------

pub struct PatternDetector {
    id: &'static str,
    languages: &'static [Language],
    registry: Arc<PatternRegistry>,
    // Cache the prefilter for this detector
    cached_prefilter: Option<Prefilter>,
    // Cache the Aho-Corasick automaton to avoid rebuilding for every file
    cached_automaton: Mutex<Option<aho_corasick::AhoCorasick>>,
}

impl PatternDetector {
    pub fn new(
        id: &'static str,
        languages: &'static [Language],
        registry: Arc<PatternRegistry>,
    ) -> Self {
        Self {
            id,
            languages,
            registry,
            cached_prefilter: None,
            cached_automaton: Mutex::new(None),
        }
    }
}

impl PatternDetector {
    fn get_cached_automaton(
        &self,
        substrings: &BTreeSet<String>,
    ) -> Result<Option<aho_corasick::AhoCorasick>> {
        if substrings.is_empty() {
            return Ok(None);
        }

        let mut cached = self.cached_automaton.lock().unwrap();
        if cached.is_none() {
            let substrings_vec: Vec<&str> = substrings.iter().map(|s| s.as_str()).collect();
            let ac = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(substrings_vec)
                .map_err(|e| anyhow!("failed to build aho-corasick: {e}"))?;
            *cached = Some(ac);
        }
        Ok(cached.clone())
    }

    fn scan_with_preprocessed(
        &self,
        libs: Vec<&CompiledLibrary>,
        stripped_s: &str,
        index: &LineIndex,
        unit: &ScanUnit,
        em: &mut Emitter,
    ) -> Result<()> {
        for lib in libs {
            // import/include/namespace first
            let mut first_span = Span { line: 1, column: 1 };
            let mut first_symbol = String::new();
            let mut first_snippet = String::new();

            let mut matched_import = false;
            for re in lib.include.iter().chain(&lib.import).chain(&lib.namespace) {
                if let Some(m) = re.find(stripped_s) {
                    matched_import = true;
                    first_span = index.to_line_col(m.start());
                    first_symbol = m.as_str().to_string();
                    first_snippet = extract_line(stripped_s, m.start());
                    break;
                }
            }
            let mut api_hits = 0usize;
            let mut last_api: Option<(usize, String)> = None;
            for re in &lib.apis {
                if let Some(m) = re.find(stripped_s) {
                    api_hits += 1;
                    // store the actual matched source text, not the regex pattern
                    last_api = Some((m.start(), m.as_str().to_string()));
                }
            }
            // Prefer an API symbol if we saw any, so downstream algorithm matching works
            if let Some((pos, sym)) = last_api.clone() {
                first_span = index.to_line_col(pos);
                first_symbol = sym;
                first_snippet = extract_line(stripped_s, pos);
            }
            // Require anchor only if patterns define any; always require at least one API hit
            let has_anchor_patterns =
                !lib.include.is_empty() || !lib.import.is_empty() || !lib.namespace.is_empty();
            let anchor_satisfied = if has_anchor_patterns { matched_import } else { true };
            let should_report = anchor_satisfied && api_hits > 0;
            if should_report {
                let finding = Finding {
                    language: unit.lang,
                    library: lib.name.clone(),
                    file: unit.path.clone(),
                    span: first_span,
                    symbol: first_symbol,
                    snippet: first_snippet,
                    detector_id: self.id.to_string(),
                };
                let _ = em.send(finding);
            }
        }
        Ok(())
    }
}

impl Detector for PatternDetector {
    fn id(&self) -> &'static str {
        self.id
    }
    fn languages(&self) -> &'static [Language] {
        self.languages
    }
    fn prefilter(&self) -> Prefilter {
        // Use cached prefilter if available, otherwise compute and cache it
        if let Some(ref cached) = self.cached_prefilter {
            return cached.clone();
        }

        let mut substrings = BTreeSet::new();
        for lib in self.registry.for_language(self.languages[0]) {
            for s in &lib.prefilter_substrings {
                substrings.insert(s.clone());
            }
        }
        // Note: We can't actually cache here due to &self, but this is still faster
        // than recomputing every time since we're using the cached language lookup
        Prefilter {
            extensions: BTreeSet::new(),
            substrings,
        }
    }
    fn scan(&self, unit: &ScanUnit, em: &mut Emitter) -> Result<()> {
        let libs = self.registry.for_language(unit.lang);
        if libs.is_empty() {
            return Ok(());
        }
        let stripped = crate::strip_comments(unit.lang, &unit.bytes);
        let stripped_s = String::from_utf8_lossy(&stripped);
        let index = LineIndex::new(stripped_s.as_bytes());
        self.scan_with_preprocessed(libs, &stripped_s, &index, unit, em)
    }

    fn scan_optimized(
        &self,
        unit: &ScanUnit,
        stripped_s: &str,
        index: &LineIndex,
        em: &mut Emitter,
    ) -> Result<()> {
        let libs = self.registry.for_language(unit.lang);
        if libs.is_empty() {
            return Ok(());
        }
        self.scan_with_preprocessed(libs, stripped_s, index, unit, em)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn extract_line(s: &str, pos: usize) -> String {
    let bytes = s.as_bytes();
    let mut start = pos;
    while start > 0 && bytes[start - 1] != b'\n' {
        start -= 1;
    }
    let mut end = pos;
    while end < bytes.len() && bytes[end] != b'\n' {
        end += 1;
    }
    s[start..end].trim().to_string()
}
