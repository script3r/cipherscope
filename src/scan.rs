use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use anyhow::{Context, Result};
use regex::{Regex, RegexSet};
use tree_sitter::{Language as TsLanguage, Node, Parser, Point, Tree};

use crate::patterns::{Language, ParameterPattern, PatternSet};

macro_rules! define_ts_lang {
    ($name:ident, $feature:literal, $grammar:expr) => {
        #[cfg(feature = $feature)]
        fn $name() -> TsLanguage {
            $grammar.into()
        }
        #[cfg(not(feature = $feature))]
        fn $name() -> TsLanguage {
            unreachable!(concat!($feature, " feature disabled"))
        }
    };
}

define_ts_lang!(ts_lang_c, "lang-c", tree_sitter_c::LANGUAGE);
define_ts_lang!(ts_lang_cpp, "lang-cpp", tree_sitter_cpp::LANGUAGE);
define_ts_lang!(ts_lang_java, "lang-java", tree_sitter_java::LANGUAGE);
define_ts_lang!(ts_lang_python, "lang-python", tree_sitter_python::LANGUAGE);
define_ts_lang!(ts_lang_go, "lang-go", tree_sitter_go::LANGUAGE);
define_ts_lang!(ts_lang_swift, "lang-swift", tree_sitter_swift::LANGUAGE);
define_ts_lang!(ts_lang_php, "lang-php", tree_sitter_php::LANGUAGE_PHP);
define_ts_lang!(ts_lang_objc, "lang-objc", tree_sitter_objc::LANGUAGE);
define_ts_lang!(ts_lang_rust, "lang-rust", tree_sitter_rust::LANGUAGE);

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
    let mut include_patterns = Vec::new();
    let mut include_owners = Vec::new();

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
            continue;
        }
        for re in &lib.include_regexes {
            include_patterns.push(re.as_str().to_string());
            include_owners.push(&lib.name);
        }
    }

    if include_patterns.is_empty() {
        return hits;
    }

    let include_set = RegexSet::new(&include_patterns).expect("valid include regexes");
    for node in import_like_nodes(lang, tree.root_node()) {
        let text = node.utf8_text(content.as_bytes()).unwrap_or("");
        let matches = include_set.matches(text);
        if matches.matched_any() {
            let Point { row, column } = node.start_position();
            for idx in matches.iter() {
                hits.push(LibraryHit {
                    library_name: include_owners[idx],
                    line: row + 1,
                    column: column + 1,
                });
            }
        }
    }
    hits
}

pub fn has_anchor_hint(lang: Language, content: &str, patterns: &PatternSet) -> bool {
    if let Some(include_set) = patterns.include_sets.get(&lang)
        && include_set.is_match(content)
    {
        return true;
    }

    if let Some(api_set) = patterns.api_sets.get(&lang)
        && api_set.is_match(content)
    {
        return true;
    }

    false
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
    let mut primitive_by_alg: HashMap<String, String> = HashMap::new();
    for alg in &lib.algorithms {
        if let Some(primitive) = &alg.primitive {
            primitive_by_alg.insert(alg.name.clone(), primitive.clone());
        }
    }
    let constants = collect_constants(lang, content);
    // Collect raw hits
    let mut hits_by_alg: HashMap<&str, Vec<(AlgorithmHit<'a>, bool)>> = HashMap::new();
    for node in code_symbol_nodes(lang, tree.root_node()) {
        let text = node.utf8_text(content.as_bytes()).unwrap_or("");
        let resolved = if constants.is_empty() {
            None
        } else {
            Some(replace_constants_with_map(text, &constants))
        };
        let match_text = resolved
            .as_ref()
            .map(|(resolved_text, _)| resolved_text.as_str())
            .unwrap_or(text);
        for alg in &lib.algorithms {
            let mut match_offset = None;
            let mut matched = false;
            for re in &alg.symbol_regexes {
                if let Some(m) = re.find(text) {
                    match_offset = Some(m.start());
                    matched = true;
                    break;
                }
                if text != match_text
                    && let Some(m) = re.find(match_text)
                {
                    if let Some((_, map)) = resolved.as_ref() {
                        let start = m.start();
                        let end = m.end().min(map.len());
                        if start < map.len() {
                            let mut mapped = map[start];
                            let slice = &map[start..end];
                            for i in 0..slice.len() {
                                let prev = i.checked_sub(1).map(|p| slice[p]);
                                let next = slice.get(i + 1).copied();
                                if prev == Some(slice[i])
                                    || next == Some(slice[i])
                                    || prev.is_some_and(|p| slice[i] != p + 1)
                                {
                                    mapped = slice[i];
                                    break;
                                }
                            }
                            match_offset = Some(mapped);
                        }
                    }
                    matched = true;
                    break;
                }
            }
            if matched {
                let mut metadata = HashMap::new();
                // Add primitive if present
                if let Some(primitive) = &alg.primitive {
                    metadata.insert("primitive", serde_json::Value::String(primitive.clone()));
                }
                let mut had_param_capture = false;
                for pp in &alg.parameter_patterns {
                    let source_text = match_text;
                    if let Some(val) = extract_parameter(pp, source_text) {
                        metadata.insert(pp.name.as_str(), val);
                        had_param_capture = true;
                    } else if let Some(default_val) = &pp.default_value {
                        metadata
                            .entry(pp.name.as_str())
                            .or_insert(default_val.clone());
                    }
                }
                let Point { row, column } = node.start_position();
                let (line, column) = match_offset
                    .map(|offset| line_col_from_offset(content, node.start_byte() + offset))
                    .unwrap_or((row + 1, column + 1));
                let hit = AlgorithmHit {
                    algorithm_name: &alg.name,
                    line,
                    column,
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

    // Swift fallback: regex scan for missing algorithms.
    if matches!(lang, Language::Swift)
        && let Some(lib) = patterns.libraries.iter().find(|l| l.name == library_name)
    {
        let mut seen_on_line: HashSet<(&str, usize)> = result
            .iter()
            .map(|hit| (hit.algorithm_name, hit.line))
            .collect();
        let present_algs: HashSet<&str> = result.iter().map(|hit| hit.algorithm_name).collect();
        for alg in &lib.algorithms {
            if present_algs.contains(alg.name.as_str()) {
                continue;
            }
            for re in &alg.symbol_regexes {
                for m in re.find_iter(content) {
                    let (line, column) = line_col_from_offset(content, m.start());
                    if seen_on_line.insert((&alg.name, line)) {
                        let mut metadata = HashMap::new();
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

    dedupe_more_specific(result, &primitive_by_alg)
}

pub fn dedupe_more_specific_hits<'a>(hits: Vec<AlgorithmHit<'a>>) -> Vec<AlgorithmHit<'a>> {
    let mut drop = vec![false; hits.len()];
    for i in 0..hits.len() {
        if drop[i] {
            continue;
        }
        for j in 0..hits.len() {
            if i == j || drop[j] {
                continue;
            }
            if hits[i].line != hits[j].line {
                continue;
            }
            let Some(p_i) = primitive_of_metadata(&hits[i]) else {
                continue;
            };
            let Some(p_j) = primitive_of_metadata(&hits[j]) else {
                continue;
            };
            if p_i != p_j {
                continue;
            }
            if is_more_specific(hits[j].algorithm_name, hits[i].algorithm_name) {
                drop[i] = true;
                break;
            }
        }
    }

    hits.into_iter()
        .enumerate()
        .filter_map(|(idx, hit)| if drop[idx] { None } else { Some(hit) })
        .collect()
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

fn collect_constants(lang: Language, content: &str) -> HashMap<String, String> {
    let mut constants = HashMap::new();
    let patterns: &[&str] = match lang {
        Language::C | Language::Cpp | Language::Objc => &[
            r"(?m)^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+([^\n]+)$",
            r"(?m)^\s*(?:static\s+)?const\s+[^=;]+?\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);",
        ],
        Language::Java => &[
            r"(?m)^\s*(?:public|private|protected)?\s*(?:static\s+)?final\s+(?:int|long|String)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);",
        ],
        Language::Go => &[r"(?m)^\s*const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\n]+)$"],
        Language::Python => &[r"(?m)^\s*([A-Z_][A-Z0-9_]*)\s*=\s*([^#\n]+)"],
        Language::Php => &[
            r"(?m)^\s*const\s+([A-Z_][A-Z0-9_]*)\s*=\s*([^;]+);",
            r#"define\(\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*,\s*([^)]+)\)"#,
        ],
        Language::Rust => &[r"(?m)^\s*const\s+([A-Za-z_][A-Za-z0-9_]*)\s*:[^=]+=\s*([^;]+);"],
        _ => &[],
    };

    for pattern in patterns {
        let re = Regex::new(pattern).expect("valid regex");
        for caps in re.captures_iter(content) {
            let Some(name) = caps.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let Some(raw_value) = caps.get(2).map(|m| m.as_str()) else {
                continue;
            };
            if let Some(value) = normalize_const_value(raw_value) {
                constants.insert(name.to_string(), value);
            }
        }
    }

    constants
}

fn normalize_const_value(raw: &str) -> Option<String> {
    let mut value = raw.trim();
    if let Some((before, _)) = value.split_once("//") {
        value = before.trim();
    }
    if let Some((before, _)) = value.split_once("/*") {
        value = before.trim();
    }
    value = value.trim_end_matches(';').trim_end_matches(',').trim();
    while value.starts_with('(') && value.ends_with(')') && value.len() > 2 {
        value = value[1..value.len() - 1].trim();
    }
    if value.is_empty() {
        return None;
    }
    if value.starts_with('"') || value.starts_with('\'') {
        return Some(value.to_string());
    }

    let mut digits = String::new();
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else {
            break;
        }
    }
    if !digits.is_empty() {
        let suffix = value[digits.len()..].trim();
        if suffix.is_empty() || suffix.chars().all(|c| c.is_ascii_alphabetic()) {
            return Some(digits);
        }
    }

    if is_identifier(value) {
        return Some(value.to_string());
    }

    None
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn replace_constants_with_map(
    text: &str,
    constants: &HashMap<String, String>,
) -> (String, Vec<usize>) {
    if constants.is_empty() {
        let map = (0..text.len()).collect::<Vec<_>>();
        return (text.to_string(), map);
    }

    let mut resolved = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len());
    let mut token = String::new();
    let mut token_start = None;

    let flush_token = |resolved: &mut String,
                       map: &mut Vec<usize>,
                       token: &mut String,
                       token_start: &mut Option<usize>,
                       end: usize| {
        if let Some(start) = token_start.take() {
            if let Some(value) = constants.get(token) {
                resolved.push_str(value);
                for _ in 0..value.len() {
                    map.push(start);
                }
            } else {
                resolved.push_str(&text[start..end]);
                for idx in start..end {
                    map.push(idx);
                }
            }
            token.clear();
        }
    };

    for (idx, ch) in text.char_indices() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            if token_start.is_none() {
                token_start = Some(idx);
            }
            token.push(ch);
        } else {
            flush_token(&mut resolved, &mut map, &mut token, &mut token_start, idx);
            resolved.push(ch);
            for b in 0..ch.len_utf8() {
                map.push(idx + b);
            }
        }
    }
    flush_token(
        &mut resolved,
        &mut map,
        &mut token,
        &mut token_start,
        text.len(),
    );

    (resolved, map)
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
            Language::Swift => matches!(kind, "call_expression" | "member_access_expression"),
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

fn dedupe_more_specific<'a>(
    hits: Vec<AlgorithmHit<'a>>,
    primitive_by_alg: &HashMap<String, String>,
) -> Vec<AlgorithmHit<'a>> {
    let mut drop = vec![false; hits.len()];
    for i in 0..hits.len() {
        if drop[i] {
            continue;
        }
        for j in 0..hits.len() {
            if i == j || drop[j] {
                continue;
            }
            if hits[i].line != hits[j].line {
                continue;
            }
            if !primitives_compatible(&hits[i], &hits[j], primitive_by_alg) {
                continue;
            }
            if is_more_specific(hits[j].algorithm_name, hits[i].algorithm_name) {
                drop[i] = true;
                break;
            }
        }
    }

    hits.into_iter()
        .enumerate()
        .filter_map(|(idx, hit)| if drop[idx] { None } else { Some(hit) })
        .collect()
}

fn primitive_of<'a>(
    hit: &'a AlgorithmHit<'a>,
    primitive_by_alg: &'a HashMap<String, String>,
) -> Option<&'a str> {
    hit.metadata
        .get("primitive")
        .and_then(|v| v.as_str())
        .or_else(|| primitive_by_alg.get(hit.algorithm_name).map(|s| s.as_str()))
}

fn primitive_of_metadata<'a>(hit: &'a AlgorithmHit<'a>) -> Option<&'a str> {
    hit.metadata.get("primitive").and_then(|v| v.as_str())
}

fn primitives_compatible<'a>(
    left: &'a AlgorithmHit<'a>,
    right: &'a AlgorithmHit<'a>,
    primitive_by_alg: &'a HashMap<String, String>,
) -> bool {
    match (
        primitive_of(left, primitive_by_alg),
        primitive_of(right, primitive_by_alg),
    ) {
        (Some(p_left), Some(p_right)) => p_left == p_right,
        _ => true,
    }
}

fn is_more_specific(specific: &str, generic: &str) -> bool {
    if specific == generic {
        return false;
    }
    if specific.starts_with(generic) && specific.as_bytes().get(generic.len()) == Some(&b'-') {
        return true;
    }

    let tokens_specific: Vec<&str> = specific.split('-').collect();
    let tokens_generic: Vec<&str> = generic.split('-').collect();
    let tokens_specific_no_num: Vec<&str> = tokens_specific
        .iter()
        .copied()
        .filter(|t| !t.chars().all(|c| c.is_ascii_digit()))
        .collect();
    let tokens_generic_no_num: Vec<&str> = tokens_generic
        .iter()
        .copied()
        .filter(|t| !t.chars().all(|c| c.is_ascii_digit()))
        .collect();

    tokens_specific_no_num == tokens_generic_no_num
        && tokens_specific.len() > tokens_generic.len()
        && tokens_specific
            .iter()
            .any(|t| t.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::{
        AlgorithmHit, dedupe_more_specific_hits, find_library_anchors, has_anchor_hint, parse,
    };
    use crate::patterns::{Language, PatternSet};
    use ahash::AHashMap as HashMap;
    use serde_json::Value;

    fn hit(
        algorithm_name: &'static str,
        line: usize,
        column: usize,
        primitive: Option<&'static str>,
    ) -> AlgorithmHit<'static> {
        let mut metadata: HashMap<&'static str, Value> = HashMap::new();
        if let Some(p) = primitive {
            metadata.insert("primitive", Value::String(p.to_string()));
        }
        AlgorithmHit {
            algorithm_name,
            line,
            column,
            metadata,
        }
    }

    #[test]
    fn dedupe_drops_generic_when_more_specific_same_line() {
        let hits = vec![
            hit("AES", 10, 5, Some("symmetric")),
            hit("AES-CBC", 10, 5, Some("symmetric")),
        ];
        let out = dedupe_more_specific_hits(hits);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].algorithm_name, "AES-CBC");
    }

    #[test]
    fn dedupe_keeps_generic_on_different_lines() {
        let hits = vec![
            hit("AES", 10, 5, Some("symmetric")),
            hit("AES-CBC", 11, 5, Some("symmetric")),
        ];
        let out = dedupe_more_specific_hits(hits);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn dedupe_keeps_different_primitives() {
        let hits = vec![
            hit("AES", 10, 5, Some("symmetric")),
            hit("AES-CTR", 10, 5, Some("asymmetric")),
        ];
        let out = dedupe_more_specific_hits(hits);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn dedupe_handles_numeric_specificity() {
        let hits = vec![
            hit("ECDSA", 20, 3, Some("signature")),
            hit("ECDSA-P256", 20, 3, Some("signature")),
        ];
        let out = dedupe_more_specific_hits(hits);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].algorithm_name, "ECDSA-P256");
    }

    #[test]
    fn dedupe_requires_primitive_metadata() {
        let hits = vec![
            hit("AES", 10, 5, None),
            hit("AES-CBC", 10, 5, Some("symmetric")),
        ];
        let out = dedupe_more_specific_hits(hits);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn dedupe_keeps_multiple_specific_variants() {
        let hits = vec![
            hit("AES", 10, 5, Some("symmetric")),
            hit("AES-CBC", 10, 6, Some("symmetric")),
            hit("AES-CTR", 10, 7, Some("symmetric")),
        ];
        let out = dedupe_more_specific_hits(hits);
        assert_eq!(out.len(), 2);
        let names: Vec<&str> = out.iter().map(|h| h.algorithm_name).collect();
        assert!(names.contains(&"AES-CBC"));
        assert!(names.contains(&"AES-CTR"));
    }

    #[test]
    fn dedupe_keeps_duplicate_specific_hits() {
        let hits = vec![
            hit("AES", 10, 10, Some("symmetric")),
            hit("AES-CBC", 10, 5, Some("symmetric")),
            hit("AES-CBC", 10, 20, Some("symmetric")),
        ];
        let out = dedupe_more_specific_hits(hits);
        assert_eq!(out.len(), 2);
        let mut cbc_hits = out
            .iter()
            .filter(|h| h.algorithm_name == "AES-CBC")
            .collect::<Vec<_>>();
        assert_eq!(cbc_hits.len(), 2);
        cbc_hits.sort_by_key(|h| h.column);
        assert_eq!(cbc_hits[0].column, 5);
        assert_eq!(cbc_hits[1].column, 20);
    }

    #[test]
    fn dedupe_avoids_prefix_collisions() {
        let hits = vec![
            hit("AES", 10, 5, Some("symmetric")),
            hit("RSAES-OAEP", 10, 8, Some("asymmetric")),
        ];
        let out = dedupe_more_specific_hits(hits);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn dedupe_allows_cross_library_overlap() {
        let hits = vec![
            hit("AES", 10, 5, Some("symmetric")),
            hit("AES-CBC", 10, 6, Some("symmetric")),
            hit("AES", 10, 8, Some("hash")),
        ];
        let out = dedupe_more_specific_hits(hits);
        assert_eq!(out.len(), 2);
        let names: Vec<(&str, &str)> = out
            .iter()
            .map(|h| {
                (
                    h.algorithm_name,
                    h.metadata
                        .get("primitive")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                )
            })
            .collect();
        assert!(names.contains(&("AES-CBC", "symmetric")));
        assert!(names.contains(&("AES", "hash")));
    }

    #[test]
    fn dedupe_after_constant_resolution_like_hit() {
        let hits = vec![
            hit("AES", 12, 3, Some("symmetric")),
            hit("AES-GCM", 12, 3, Some("symmetric")),
        ];
        let out = dedupe_more_specific_hits(hits);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].algorithm_name, "AES-GCM");
    }

    fn patterns_from_toml(text: &str) -> PatternSet {
        PatternSet::from_toml(text).expect("valid patterns")
    }

    #[test]
    fn has_anchor_hint_detects_include_and_api() {
        let patterns = patterns_from_toml(
            r#"
[[library]]
name = "TestLib"
languages = ["Python"]
[library.patterns]
include = ["import\\s+testlib"]
apis = ["testlib\\.crypto"]
"#,
        );
        assert!(has_anchor_hint(
            Language::Python,
            "import testlib\nx = 1",
            &patterns
        ));
        assert!(has_anchor_hint(
            Language::Python,
            "testlib.crypto()",
            &patterns
        ));
        assert!(!has_anchor_hint(
            Language::Python,
            "print('nope')",
            &patterns
        ));
    }

    #[test]
    fn find_library_anchors_uses_import_nodes() {
        let patterns = patterns_from_toml(
            r#"
[[library]]
name = "TestLib"
languages = ["Python"]
[library.patterns]
include = ["testlib"]
"#,
        );
        let content = "import testlib\nx = 1";
        let tree = parse(Language::Python, content).expect("parse python");
        let hits = find_library_anchors(Language::Python, content, &tree, &patterns);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].library_name, "TestLib");
        assert_eq!(hits[0].line, 1);
        assert_eq!(hits[0].column, 1);
    }

    #[test]
    fn find_library_anchors_falls_back_to_api_regex() {
        let patterns = patterns_from_toml(
            r#"
[[library]]
name = "TestLib"
languages = ["Python"]
[library.patterns]
apis = ["CryptoLib"]
"#,
        );
        let content = "CryptoLib.new()\n";
        let tree = parse(Language::Python, content).expect("parse python");
        let hits = find_library_anchors(Language::Python, content, &tree, &patterns);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].library_name, "TestLib");
        assert_eq!(hits[0].line, 1);
        assert_eq!(hits[0].column, 1);
    }
}
