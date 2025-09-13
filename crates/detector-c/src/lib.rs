use std::sync::Arc;
use scanner_core::{Detector, Language, PatternDetector, PatternRegistry};

pub fn make(registry: Arc<PatternRegistry>) -> Box<dyn Detector> {
    Box::new(PatternDetector::new("detector-c", &[Language::C], registry))
}

