use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use anyhow::Result;
use serde::Serialize;
use std::sync::LazyLock;

pub mod patterns;
pub mod scan;

pub const DEFAULT_PATTERNS: &str = include_str!("../patterns.toml");

#[derive(Serialize, Clone)]
pub struct Evidence {
    pub line: usize,
    pub column: usize,
}

#[derive(Serialize, Clone)]
pub struct Finding {
    #[serde(rename = "assetType")]
    pub asset_type: String,
    pub identifier: String,
    pub path: String,
    pub evidence: Evidence,
    #[serde(skip_serializing_if = "map_is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

fn map_is_empty(m: &HashMap<String, serde_json::Value>) -> bool {
    m.is_empty()
}

static PATTERNS: LazyLock<patterns::PatternSet> = LazyLock::new(|| {
    patterns::PatternSet::from_toml(DEFAULT_PATTERNS).expect("valid patterns.toml")
});

pub fn scan_snippet(
    content: &str,
    lang: patterns::Language,
    source_label: &str,
) -> Result<Vec<Finding>> {
    scan_with_patterns(content, lang, source_label, &PATTERNS)
}

/// Scans source text using a caller-supplied pattern set.
///
/// This is the shared scanning pipeline used by both the library convenience API
/// and the command-line application.
pub fn scan_with_patterns(
    content: &str,
    lang: patterns::Language,
    source_label: &str,
    patterns: &patterns::PatternSet,
) -> Result<Vec<Finding>> {
    if !scan::has_anchor_hint(lang, content, patterns) {
        return Ok(Vec::new());
    }

    let tree = scan::parse(lang, content)?;
    let lib_hits = scan::find_library_anchors(lang, content, &tree, patterns);
    if lib_hits.is_empty() {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    let mut alg_hits_all = Vec::new();

    let mut scanned_libraries = HashSet::new();
    for lib in lib_hits {
        if !scanned_libraries.insert(lib.library_name) {
            continue;
        }

        let evidence = Evidence {
            line: lib.line,
            column: lib.column,
        };
        findings.push(Finding {
            asset_type: "library".to_string(),
            identifier: lib.library_name.to_string(),
            path: source_label.to_string(),
            evidence,
            metadata: HashMap::new(),
        });

        let alg_hits = scan::find_algorithms(lang, content, &tree, patterns, lib.library_name);
        alg_hits_all.extend(alg_hits);
    }

    let alg_hits_all = scan::dedupe_more_specific_hits(alg_hits_all);
    let mut seen_algorithms = HashSet::new();
    for alg in alg_hits_all {
        if !seen_algorithms.insert((alg.algorithm_name, alg.line, alg.column)) {
            continue;
        }
        let mut metadata = HashMap::new();
        for (k, v) in alg.metadata {
            metadata.insert(k.to_string(), v);
        }
        let evidence = Evidence {
            line: alg.line,
            column: alg.column,
        };
        findings.push(Finding {
            asset_type: "algorithm".to_string(),
            identifier: alg.algorithm_name.to_string(),
            path: source_label.to_string(),
            evidence,
            metadata,
        });
    }

    Ok(findings)
}
