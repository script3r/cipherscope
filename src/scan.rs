use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use anyhow::{Context, Result};
use tree_sitter::{Language as TsLanguage, Node, Parser, Point, Tree};

use crate::patterns::{Language, ParameterPattern, PatternSet};

#[cfg(feature = "lang-c")]
fn ts_lang_c() -> TsLanguage {
    tree_sitter_c::LANGUAGE.into()
}
#[cfg(not(feature = "lang-c"))]
fn ts_lang_c() -> TsLanguage {
    unreachable!("lang-c feature disabled")
}

#[cfg(feature = "lang-cpp")]
fn ts_lang_cpp() -> TsLanguage {
    tree_sitter_cpp::LANGUAGE.into()
}
#[cfg(not(feature = "lang-cpp"))]
fn ts_lang_cpp() -> TsLanguage {
    unreachable!("lang-cpp feature disabled")
}

#[cfg(feature = "lang-java")]
fn ts_lang_java() -> TsLanguage {
    tree_sitter_java::LANGUAGE.into()
}
#[cfg(not(feature = "lang-java"))]
fn ts_lang_java() -> TsLanguage {
    unreachable!("lang-java feature disabled")
}

#[cfg(feature = "lang-python")]
fn ts_lang_python() -> TsLanguage {
    tree_sitter_python::LANGUAGE.into()
}
#[cfg(not(feature = "lang-python"))]
fn ts_lang_python() -> TsLanguage {
    unreachable!("lang-python feature disabled")
}

#[cfg(feature = "lang-go")]
fn ts_lang_go() -> TsLanguage {
    tree_sitter_go::LANGUAGE.into()
}
#[cfg(not(feature = "lang-go"))]
fn ts_lang_go() -> TsLanguage {
    unreachable!("lang-go feature disabled")
}

#[cfg(feature = "lang-swift")]
fn ts_lang_swift() -> TsLanguage {
    tree_sitter_swift::LANGUAGE.into()
}
#[cfg(feature = "lang-php")]
fn ts_lang_php() -> TsLanguage {
    tree_sitter_php::LANGUAGE_PHP.into()
}
#[cfg(not(feature = "lang-php"))]
fn ts_lang_php() -> TsLanguage {
    unreachable!("lang-php feature disabled")
}
#[cfg(not(feature = "lang-swift"))]
fn ts_lang_swift() -> TsLanguage {
    unreachable!("lang-swift feature disabled")
}

#[cfg(feature = "lang-objc")]
fn ts_lang_objc() -> TsLanguage {
    tree_sitter_objc::LANGUAGE.into()
}
#[cfg(not(feature = "lang-objc"))]
fn ts_lang_objc() -> TsLanguage {
    unreachable!("lang-objc feature disabled")
}

#[cfg(feature = "lang-rust")]
fn ts_lang_rust() -> TsLanguage {
    tree_sitter_rust::LANGUAGE.into()
}
#[cfg(not(feature = "lang-rust"))]
fn ts_lang_rust() -> TsLanguage {
    unreachable!("lang-rust feature disabled")
}

#[derive(Clone, Copy, Debug)]
pub struct LibraryHit<'a> {
    pub library_name: &'a str,
    pub line: usize,
    pub column: usize,
}

#[derive(Clone, Debug)]
pub struct AlgorithmHit<'a> {
    pub algorithm_name: &'a str,
    pub line: usize,
    pub column: usize,
    pub metadata: HashMap<&'a str, serde_json::Value>,
}

pub fn language_from_path(path: &std::path::Path) -> Option<Language> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "c" => Some(Language::C),
        "h" => Some(Language::Cpp), // Parse .h as C++ since it's backwards compatible with C
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => Some(Language::Cpp),
        "java" => Some(Language::Java),
        "py" => Some(Language::Python),
        "go" => Some(Language::Go),
        "swift" => Some(Language::Swift),
        "php" | "hack" => Some(Language::Php),
        "m" | "mm" => Some(Language::Objc),
        "rs" => Some(Language::Rust),
        _ => None,
    }
}

/// Parses the given string content into a `tree-sitter` syntax tree.
///
/// This function selects the appropriate `tree-sitter` grammar based on the `lang`
/// parameter and uses it to construct an AST. This tree is the foundation for all
/// subsequent static analysis.
pub fn parse(lang: Language, content: &str) -> Result<Tree> {
    let mut parser = Parser::new();
    let ts_lang = match lang {
        Language::C => ts_lang_c(),
        Language::Cpp => ts_lang_cpp(),
        Language::Java => ts_lang_java(),
        Language::Python => ts_lang_python(),
        Language::Go => ts_lang_go(),
        Language::Swift => ts_lang_swift(),
        Language::Php => ts_lang_php(),
        Language::Objc => ts_lang_objc(),
        Language::Rust => ts_lang_rust(),
    };
    parser.set_language(&ts_lang).context("set language")?;
    
    // Allow deprecated method for now - the new API is more complex
    // and the current method works fine for our needs
    #[allow(deprecated)]
    parser.set_timeout_micros(5_000_000); // 5 second timeout
    
    parser.parse(content, None).context("parse")
}

/// Scans the AST to find "library anchors" which are top-level import-like
/// statements that indicate the use of a known cryptographic library.
///
/// This is the first step in the scanning process for a file. By identifying
/// library usage first (e.g., `#include <openssl/evp.h>` or `import cryptography`),
/// we can narrow down the search for specific algorithms to just the patterns
/// associated with that library, improving both performance and accuracy.
///
/// If a library pattern set has no `include_regexes`, it falls back to a coarse
/// scan of the entire file content using `api_regexes`.
pub fn find_library_anchors<'a>(
    lang: Language,
    content: &'a str,
    tree: &Tree,
    patterns: &'a PatternSet,
) -> Vec<LibraryHit<'a>> {
    let mut hits = Vec::new();
    for lib in &patterns.libraries {
        if !lib.languages.contains(&lang) {
            continue;
        }
        if lib.include_regexes.is_empty() {
            // Fallback: scan entire content with api_regexes as a coarse anchor (no AST import nodes)
            if lib.api_regexes.iter().any(|re| re.is_match(content)) {
                hits.push(LibraryHit {
                    library_name: &lib.name,
                    line: 1,
                    column: 1,
                });
            }
        } else {
            for node in import_like_nodes(lang, tree.root_node()) {
                let text = node.utf8_text(content.as_bytes()).unwrap_or("");
                if lib.include_regexes.iter().any(|re| re.is_match(text)) {
                    let Point { row, column } = node.start_position();
                    hits.push(LibraryHit {
                        library_name: &lib.name,
                        line: row + 1,
                        column: column + 1,
                    });
                }
            }
        }
    }
    hits
}

/// After a library has been identified, this function scans the AST for specific
/// algorithm usage patterns associated with that library.
///
/// It iterates through code symbols (like function calls and identifiers) and
/// matches them against the `symbol_regexes` for each algorithm defined in the
/// pattern set for the given `library_name`.
///
/// It also handles extraction of parameters (e.g., key sizes) from the code
/// using the `parameter_patterns` regexes, adding them as metadata to the finding.
/// To reduce noise, if any finding for a given algorithm has captured parameters,
/// only those findings are kept, and parameter-less findings are discarded.
pub fn find_algorithms<'a>(
    lang: Language,
    content: &'a str,
    tree: &Tree,
    patterns: &'a PatternSet,
    library_name: &'a str,
) -> Vec<AlgorithmHit<'a>> {
    let mut result = Vec::new();
    let Some(lib) = patterns.libraries.iter().find(|l| l.name == library_name) else {
        return result;
    };
    // Collect raw hits
    let mut hits_by_alg: HashMap<&str, Vec<(AlgorithmHit<'a>, bool)>> = HashMap::new();
    for node in code_symbol_nodes(lang, tree.root_node()) {
        let text = node.utf8_text(content.as_bytes()).unwrap_or("");
        for alg in &lib.algorithms {
            if alg.symbol_regexes.iter().any(|re| re.is_match(text)) {
                let mut metadata = HashMap::new();
                // Add primitive if present
                if let Some(primitive) = &alg.primitive {
                    metadata.insert("primitive", serde_json::Value::String(primitive.clone()));
                }
                let mut had_param_capture = false;
                for pp in &alg.parameter_patterns {
                    if let Some(val) = extract_parameter(pp, text) {
                        metadata.insert(pp.name.as_str(), val);
                        had_param_capture = true;
                    } else if let Some(default_val) = &pp.default_value {
                        metadata
                            .entry(pp.name.as_str())
                            .or_insert(default_val.clone());
                    }
                }
                let Point { row, column } = node.start_position();
                let hit = AlgorithmHit {
                    algorithm_name: &alg.name,
                    line: row + 1,
                    column: column + 1,
                    metadata,
                };
                hits_by_alg
                    .entry(&alg.name)
                    .or_default()
                    .push((hit, had_param_capture));
            }
        }
    }

    // For each algorithm: if any hit had parameter captures, only keep those; otherwise keep all
    // Also deduplicate by (algorithm_name, line) - keep the first occurrence
    let mut seen_on_line: HashSet<(&str, usize)> = HashSet::new();
    for (_alg_name, mut hits) in hits_by_alg {
        // Sort by column to ensure we keep the first occurrence on each line
        hits.sort_by_key(|(hit, _)| (hit.line, hit.column));
        let any_param = hits.iter().any(|(_, had)| *had);
        if any_param {
            for (hit, _had) in hits.into_iter().filter(|(_, had)| *had) {
                if seen_on_line.insert((hit.algorithm_name, hit.line)) {
                    result.push(hit);
                }
            }
        } else {
            for (hit, _) in hits {
                if seen_on_line.insert((hit.algorithm_name, hit.line)) {
                    result.push(hit);
                }
            }
        }
    }

    // Java fallback: regex scan
    if result.is_empty()
        && matches!(lang, Language::Java)
        && let Some(lib) = patterns.libraries.iter().find(|l| l.name == library_name)
    {
        let mut seen_on_line: HashSet<(&str, usize)> = HashSet::new();
        for alg in &lib.algorithms {
            for re in &alg.symbol_regexes {
                for m in re.find_iter(content) {
                    let (line, column) = line_col_from_offset(content, m.start());
                    if seen_on_line.insert((&alg.name, line)) {
                        let mut metadata = HashMap::new();
                        // Add primitive if present
                        if let Some(primitive) = &alg.primitive {
                            metadata
                                .insert("primitive", serde_json::Value::String(primitive.clone()));
                        }
                        result.push(AlgorithmHit {
                            algorithm_name: &alg.name,
                            line,
                            column,
                            metadata,
                        });
                    }
                }
            }
        }
    }

    result
}

fn line_col_from_offset(content: &str, byte_idx: usize) -> (usize, usize) {
    // 1-based line, column
    let bytes = content.as_bytes();
    let mut line = 1usize;
    let mut col = 1usize;
    let mut i = 0usize;
    while i < byte_idx && i < bytes.len() {
        if bytes[i] == b'\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
        i += 1;
    }
    (line, col)
}

fn extract_parameter(pp: &ParameterPattern, text: &str) -> Option<serde_json::Value> {
    let caps = pp.regex.captures(text)?;
    if let Some(g_match) = caps.get(1) {
        let g = g_match.as_str();
        if let Ok(n) = g.parse::<i64>() {
            return Some(serde_json::Value::from(n));
        }
        return Some(serde_json::Value::String(g.to_string()));
    }
    None
}

fn import_like_nodes<'a>(lang: Language, root: Node<'a>) -> Vec<Node<'a>> {
    let mut nodes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        let is_import = match lang {
            Language::C | Language::Cpp => kind == "preproc_include",
            Language::Java => kind == "import_declaration",
            Language::Python => kind == "import_statement" || kind == "import_from_statement",
            Language::Go => kind == "import_declaration",
            Language::Swift => kind == "import_declaration",
            Language::Php => kind == "namespace_use_declaration" || kind == "qualified_name",
            Language::Objc => kind == "preproc_import" || kind == "preproc_include",
            Language::Rust => kind == "use_declaration",
        };
        if is_import {
            nodes.push(node);
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    nodes
}

fn code_symbol_nodes<'a>(lang: Language, root: Node<'a>) -> Vec<Node<'a>> {
    // Heuristic: collect identifiers, call expressions, etc.
    let mut nodes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        let interesting = match lang {
            Language::C | Language::Cpp => matches!(kind, "call_expression"),
            Language::Java => matches!(kind, "method_invocation"),
            Language::Python => matches!(kind, "call" | "attribute"),
            Language::Go => matches!(kind, "call_expression"),
            Language::Swift => matches!(kind, "call_expression"),
            Language::Php => matches!(kind, "function_call_expression"),
            Language::Objc => matches!(kind, "call_expression" | "selector" | "identifier"),
            Language::Rust => matches!(kind, "call_expression" | "macro_invocation"),
        };
        if interesting {
            nodes.push(node);
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    nodes
}
