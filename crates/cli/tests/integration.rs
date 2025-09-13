use scanner_core::*;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn scan_fixtures() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let patterns_path = workspace.join("patterns.toml");
    let patterns = std::fs::read_to_string(patterns_path).unwrap();
    let reg = PatternRegistry::load(&patterns).unwrap();
    let reg = Arc::new(reg);
    let dets: Vec<Box<dyn Detector>> = vec![
        Box::new(PatternDetector::new(
            "detector-go",
            &[Language::Go],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-java",
            &[Language::Java],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-c",
            &[Language::C],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-cpp",
            &[Language::Cpp],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-rust",
            &[Language::Rust],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-python",
            &[Language::Python],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-php",
            &[Language::Php],
            reg.clone(),
        )),
    ];
    let scanner = Scanner::new(&reg, dets, Config::default());
    let fixtures = workspace.join("fixtures");
    let findings = scanner.run(&[fixtures.clone()]).unwrap();

    // Expect at least one hit per language category in positive fixtures
    let has_rust = findings
        .iter()
        .any(|f| matches!(f.language, Language::Rust));
    let has_python = findings
        .iter()
        .any(|f| matches!(f.language, Language::Python));
    let has_java = findings
        .iter()
        .any(|f| matches!(f.language, Language::Java));
    let has_c = findings
        .iter()
        .any(|f| matches!(f.language, Language::C | Language::Cpp));
    let has_go = findings.iter().any(|f| matches!(f.language, Language::Go));
    let has_php = findings.iter().any(|f| matches!(f.language, Language::Php));

    assert!(
        has_rust && has_python && has_java && has_c && has_go && has_php,
        "missing findings for some languages"
    );

    // Ensure comments are ignored: negative fixtures should not produce hits
    let neg = workspace.join("fixtures/negative");
    let neg_findings = scanner.run(&[neg]).unwrap();
    assert!(
        neg_findings.is_empty(),
        "expected no findings in negative fixtures, got {}",
        neg_findings.len()
    );
}
