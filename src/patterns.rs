use anyhow::{Context, Result};
use regex::{Regex, RegexSet};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    C,
    Cpp,
    Java,
    Python,
    Go,
    Swift,
    Php,
    Objc,
    Rust,
}

#[derive(Debug, Deserialize)]
struct RawPatternSet {
    #[allow(dead_code)]
    #[serde(default)]
    version: Option<RawVersion>,
    #[serde(default)]
    library: Vec<RawLibrary>,
}

#[derive(Debug, Deserialize)]
struct RawVersion {
    #[allow(dead_code)]
    #[serde(default)]
    schema: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    updated: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawLibrary {
    name: String,
    languages: Vec<String>,
    #[serde(default)]
    patterns: Option<RawLibraryPatterns>,
    #[serde(default)]
    algorithms: Vec<RawAlgorithm>,
}

#[derive(Debug, Deserialize)]
struct RawLibraryPatterns {
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    apis: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawAlgorithm {
    name: String,
    primitive: Option<String>,
    #[serde(default, rename = "nistQuantumSecurityLevel")]
    nist_quantum_security_level: Option<u8>,
    #[serde(default)]
    symbol_patterns: Vec<String>,
    #[serde(default)]
    parameter_patterns: Vec<RawParameterPattern>,
}

#[derive(Debug, Deserialize)]
struct RawParameterPattern {
    name: String,
    pattern: String,
    #[serde(default)]
    default_value: Option<toml::Value>,
}

#[derive(Debug, Clone)]
pub struct PatternSet {
    pub libraries: Vec<Library>,
    pub include_sets: HashMap<Language, RegexSet>,
    pub api_sets: HashMap<Language, RegexSet>,
}

#[derive(Debug, Clone)]
pub struct Library {
    pub name: String,
    pub languages: Vec<Language>,
    pub include_regexes: Vec<Regex>,
    pub api_regexes: Vec<Regex>,
    pub algorithms: Vec<Algorithm>,
}

#[derive(Debug, Clone)]
pub struct Algorithm {
    pub name: String,
    #[allow(dead_code)]
    pub primitive: Option<String>,
    #[allow(dead_code)]
    pub nist_level: Option<u8>,
    pub symbol_regexes: Vec<Regex>,
    pub parameter_patterns: Vec<ParameterPattern>,
}

#[derive(Debug, Clone)]
pub struct ParameterPattern {
    pub name: String,
    pub regex: Regex,
    pub default_value: Option<serde_json::Value>,
}

impl PatternSet {
    pub fn from_toml(text: &str) -> Result<Self> {
        let raw: RawPatternSet = toml::from_str(text).context("parse patterns.toml")?;
        let mut libraries = Vec::new();
        for lib in raw.library {
            let languages = lib
                .languages
                .into_iter()
                .filter_map(|s| match s.as_str() {
                    "C" => Some(Language::C),
                    "C++" => Some(Language::Cpp),
                    "Java" => Some(Language::Java),
                    "Python" => Some(Language::Python),
                    "Go" => Some(Language::Go),
                    "Swift" => Some(Language::Swift),
                    "PHP" => Some(Language::Php),
                    "ObjC" => Some(Language::Objc),
                    "Rust" => Some(Language::Rust),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if languages.is_empty() {
                continue;
            }
            let mut include_regexes = Vec::new();
            let mut api_regexes = Vec::new();
            if let Some(p) = lib.patterns {
                for re in p.include {
                    include_regexes.push(Regex::new(&re)?);
                }
                for re in p.apis {
                    api_regexes.push(Regex::new(&re)?);
                }
            }
            let mut algorithms = Vec::new();
            for a in lib.algorithms {
                let mut symbol_regexes = Vec::new();
                for re in a.symbol_patterns {
                    symbol_regexes.push(Regex::new(&re)?);
                }
                let mut parameter_patterns = Vec::new();
                for p in a.parameter_patterns {
                    parameter_patterns.push(ParameterPattern {
                        name: p.name,
                        regex: Regex::new(&p.pattern)?,
                        default_value: p.default_value.map(toml_value_to_json),
                    });
                }
                algorithms.push(Algorithm {
                    name: a.name,
                    primitive: a.primitive,
                    nist_level: a.nist_quantum_security_level,
                    symbol_regexes,
                    parameter_patterns,
                });
            }
            libraries.push(Library {
                name: lib.name,
                languages,
                include_regexes,
                api_regexes,
                algorithms,
            });
        }
        let mut include_patterns: HashMap<Language, Vec<String>> = HashMap::new();
        let mut api_patterns: HashMap<Language, Vec<String>> = HashMap::new();
        for lib in &libraries {
            for lang in &lib.languages {
                let include_entry = include_patterns.entry(*lang).or_default();
                for re in &lib.include_regexes {
                    include_entry.push(re.as_str().to_string());
                }
                let api_entry = api_patterns.entry(*lang).or_default();
                for re in &lib.api_regexes {
                    api_entry.push(re.as_str().to_string());
                }
            }
        }

        let mut include_sets = HashMap::new();
        let mut api_sets = HashMap::new();
        for (lang, patterns) in include_patterns {
            if !patterns.is_empty() {
                include_sets.insert(lang, RegexSet::new(patterns)?);
            }
        }
        for (lang, patterns) in api_patterns {
            if !patterns.is_empty() {
                api_sets.insert(lang, RegexSet::new(patterns)?);
            }
        }

        Ok(Self {
            libraries,
            include_sets,
            api_sets,
        })
    }

    pub fn supports_language(&self, lang: Language) -> bool {
        self.libraries.iter().any(|l| l.languages.contains(&lang))
    }
}

fn toml_value_to_json(v: toml::Value) -> serde_json::Value {
    match v {
        toml::Value::String(s) => serde_json::Value::String(s),
        toml::Value::Integer(i) => serde_json::Value::from(i),
        toml::Value::Float(f) => serde_json::Value::from(f),
        toml::Value::Boolean(b) => serde_json::Value::from(b),
        toml::Value::Array(a) => {
            serde_json::Value::Array(a.into_iter().map(toml_value_to_json).collect())
        }
        toml::Value::Table(t) => serde_json::Value::Object(
            t.into_iter()
                .map(|(k, v)| (k, toml_value_to_json(v)))
                .collect(),
        ),
        toml::Value::Datetime(dt) => serde_json::Value::String(dt.to_string()),
    }
}
