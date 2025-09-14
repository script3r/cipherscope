use scanner_core::{Detector, Language, ScanUnit, Emitter, Prefilter};
use anyhow::Result;
use std::collections::BTreeSet;

pub struct ErlangDetector;

impl Detector for ErlangDetector {
    fn id(&self) -> &'static str {
        "detector-erlang"
    }

    fn languages(&self) -> &'static [Language] {
        &[Language::Erlang]
    }

    fn prefilter(&self) -> Prefilter {
        Prefilter {
            extensions: BTreeSet::from([".erl".to_string(), ".hrl".to_string(), ".beam".to_string()]),
            substrings: BTreeSet::new(),
        }
    }

    fn scan(&self, _unit: &ScanUnit, _em: &mut Emitter) -> Result<()> {
        // This detector is not used since we use PatternDetector instead
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
