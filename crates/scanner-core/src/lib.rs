use aho_corasick::AhoCorasickBuilder;
use anyhow::{anyhow, Context, Result};
use crossbeam_channel::{bounded, Receiver, Sender};
use ignore::WalkBuilder;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;

// ---------------- Types ----------------

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

pub type Confidence = f32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub language: Language,
    pub library: String,
    pub file: PathBuf,
    pub span: Span,
    pub symbol: String,
    pub snippet: String,
    pub confidence: Confidence,
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
        stripped_s: &str,
        index: &LineIndex,
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

    pub fn into_iter(self) -> Receiver<Finding> {
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
pub struct Config {
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize, // bytes
    #[serde(default)]
    pub include_globs: Vec<String>,
    #[serde(default)]
    pub exclude_globs: Vec<String>,
    #[serde(default)]
    pub allow_libs: Vec<String>,
    #[serde(default)]
    pub deny_libs: Vec<String>,
    #[serde(default)]
    pub min_confidence: Option<f32>,
    #[serde(default)]
    pub deterministic: bool,
}

fn default_max_file_size() -> usize {
    2 * 1024 * 1024
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_file_size: default_max_file_size(),
            include_globs: default_include_globs(),
            exclude_globs: Vec::new(),
            allow_libs: Vec::new(),
            deny_libs: Vec::new(),
            min_confidence: None,
            deterministic: false,
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
            .map(|lib| compile_library(lib))
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
    Ok(CompiledLibrary {
        name: lib.name,
        languages: lib.languages.into_iter().collect(),
        include,
        import,
        namespace,
        apis,
        prefilter_substrings,
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

fn derive_prefilter_substrings(p: &LibraryPatterns) -> Vec<String> {
    let mut set = BTreeSet::new();
    let mut push_tokens = |s: &str| {
        for tok in s.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '/' && c != '_') {
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
            | Language::Kotlin => strip_c_like(language, input),
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

    pub fn discover_files(&self, roots: &[PathBuf]) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Build glob matcher for include patterns
        let include_matcher: Option<globset::GlobSet> = if !self.config.include_globs.is_empty() {
            let mut builder = globset::GlobSetBuilder::new();
            for pattern in &self.config.include_globs {
                match globset::Glob::new(pattern) {
                    Ok(glob) => {
                        builder.add(glob);
                    }
                    Err(_) => {
                        return Vec::new(); // Return empty on pattern error
                    }
                }
            }
            match builder.build() {
                Ok(matcher) => Some(matcher),
                Err(_) => None,
            }
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

            for result in builder.build() {
                if let Ok(entry) = result {
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

                        paths.push(path);
                    }
                }
            }
        }
        paths
    }

    pub fn detect_language(path: &Path) -> Option<Language> {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "go" => Some(Language::Go),
            "java" => Some(Language::Java),
            "c" => Some(Language::C),
            "h" => Some(Language::C),
            "hpp" => Some(Language::Cpp),
            "hh" => Some(Language::Cpp),
            "cc" | "cpp" | "cxx" => Some(Language::Cpp),
            "rs" => Some(Language::Rust),
            "py" | "pyw" | "pyi" => Some(Language::Python),
            "php" | "phtml" | "php3" | "php4" | "php5" | "phps" => Some(Language::Php),
            "swift" => Some(Language::Swift),
            "m" | "mm" | "M" => Some(Language::ObjC),
            "kt" | "kts" => Some(Language::Kotlin),
            _ => None,
        }
    }

    pub fn load_file(path: &Path) -> Result<Arc<[u8]>> {
        let mut f = fs::File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf.into())
    }

    pub fn run(&self, roots: &[PathBuf]) -> Result<Vec<Finding>> {
        let files = self.discover_files(roots);
        let mut findings: Vec<Finding> = Vec::new();

        let (tx, rx) = bounded::<Finding>(8192);
        files.par_iter().for_each_with(tx.clone(), |tx, path| {
            if let Some(lang) = Self::detect_language(path) {
                if let Ok(bytes) = Self::load_file(path) {
                    let unit = ScanUnit {
                        path: path.clone(),
                        lang,
                        bytes: bytes.clone(),
                    };
                    // Strip comments once and reuse
                    let stripped = strip_comments(lang, &bytes);
                    let stripped_s = String::from_utf8_lossy(&stripped);
                    let index = LineIndex::new(stripped_s.as_bytes());

                    let mut em = Emitter {
                        tx: tx.clone(),
                        rx: rx.clone(),
                    };
                    for det in &self.detectors {
                        if !det.languages().contains(&lang) {
                            continue;
                        }
                        if !prefilter_hit(det, &stripped) {
                            continue;
                        }
                        let _ = det.scan_optimized(&unit, &stripped_s, &index, &mut em);
                    }
                }
            }
        });

        drop(tx);
        for f in rx.iter() {
            findings.push(f);
        }

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

        if let Some(min_c) = self.config.min_confidence {
            findings.retain(|f| f.confidence >= min_c);
        }

        findings.retain(|f| {
            self.config.allow_libs.is_empty()
                || self.config.allow_libs.iter().any(|a| a == &f.library)
        });
        findings.retain(|f| !self.config.deny_libs.iter().any(|d| d == &f.library));

        Ok(findings)
    }
}

fn prefilter_hit(det: &Box<dyn Detector>, stripped: &[u8]) -> bool {
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
            let mut best_conf = 0.0f32;
            let mut first_span = Span { line: 1, column: 1 };
            let mut first_symbol = String::new();
            let mut first_snippet = String::new();

            let mut matched_import = false;
            for re in lib.include.iter().chain(&lib.import).chain(&lib.namespace) {
                if let Some(m) = re.find(stripped_s) {
                    matched_import = true;
                    best_conf = best_conf.max(0.95);
                    first_span = index.to_line_col(m.start());
                    first_symbol = re.as_str().to_string();
                    first_snippet = extract_line(stripped_s, m.start());
                    break;
                }
            }
            let mut api_hits = 0usize;
            let mut last_api: Option<(usize, String)> = None;
            for re in &lib.apis {
                if let Some(m) = re.find(stripped_s) {
                    api_hits += 1;
                    last_api = Some((m.start(), re.as_str().to_string()));
                }
            }
            if api_hits > 0 {
                best_conf = best_conf.max(if matched_import { 0.99 } else { 0.80 });
                if first_symbol.is_empty() {
                    if let Some((pos, sym)) = last_api.clone() {
                        first_span = index.to_line_col(pos);
                        first_symbol = sym;
                        first_snippet = extract_line(stripped_s, pos);
                    }
                }
            }
            let should_report =
                (matched_import && api_hits > 0) || (lib.import.is_empty() && api_hits > 0);
            if should_report {
                let finding = Finding {
                    language: unit.lang,
                    library: lib.name.clone(),
                    file: unit.path.clone(),
                    span: first_span,
                    symbol: first_symbol,
                    snippet: first_snippet,
                    confidence: best_conf,
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
        let pf = Prefilter {
            extensions: BTreeSet::new(),
            substrings,
        };

        // Note: We can't actually cache here due to &self, but this is still faster
        // than recomputing every time since we're using the cached language lookup
        pf
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
