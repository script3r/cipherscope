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
    if !scan::has_anchor_hint(lang, content, &PATTERNS) {
        return Ok(Vec::new());
    }

    let tree = scan::parse(lang, content)?;
    let lib_hits = scan::find_library_anchors(lang, content, &tree, &PATTERNS);
    if lib_hits.is_empty() {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut alg_hits_all = Vec::new();

    for lib in lib_hits {
        let evidence = Evidence {
            line: lib.line,
            column: lib.column,
        };
        let finding = Finding {
            asset_type: "library".to_string(),
            identifier: lib.library_name.to_string(),
            path: source_label.to_string(),
            evidence,
            metadata: HashMap::new(),
        };
        let key = format!("lib|{}", finding.identifier);
        if seen.insert(key) {
            findings.push(finding);
        }

        let alg_hits = scan::find_algorithms(lang, content, &tree, &PATTERNS, lib.library_name);
        alg_hits_all.extend(alg_hits);
    }

    let alg_hits_all = scan::dedupe_more_specific_hits(alg_hits_all);
    for alg in alg_hits_all {
        let mut metadata = HashMap::new();
        for (k, v) in alg.metadata {
            metadata.insert(k.to_string(), v);
        }
        let evidence = Evidence {
            line: alg.line,
            column: alg.column,
        };
        let finding = Finding {
            asset_type: "algorithm".to_string(),
            identifier: alg.algorithm_name.to_string(),
            path: source_label.to_string(),
            evidence,
            metadata,
        };
        let key = format!(
            "alg|{}|{}:{}",
            finding.identifier, finding.evidence.line, finding.evidence.column
        );
        if seen.insert(key) {
            findings.push(finding);
        }
    }

    Ok(findings)
}
