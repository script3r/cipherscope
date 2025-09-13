use scanner_core::{Detector, Language, PatternDetector, PatternRegistry};
use std::sync::Arc;

pub fn make(registry: Arc<PatternRegistry>) -> Box<dyn Detector> {
    Box::new(PatternDetector::new(
        "detector-go",
        &[Language::Go],
        registry,
    ))
}
