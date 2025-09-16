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
    let findings = scanner.run(std::slice::from_ref(&fixtures)).unwrap();

    // Debug: print all findings
    println!("Found {} findings:", findings.len());
    for f in &findings {
        println!(
            "  {:?} | {} | {}:{}",
            f.language,
            f.library,
            f.file.display(),
            f.span.line
        );
    }

    // Expect at least one hit per language category across comprehensive fixtures
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

    assert!(has_rust, "missing Rust findings");
    assert!(has_python, "missing Python findings");
    assert!(has_java, "missing Java findings");
    assert!(has_c, "missing C/C++ findings");
    assert!(has_go, "missing Go findings");
    assert!(has_php, "missing PHP findings");

    // Note: legacy negative fixtures removed; comprehensive fixtures are used now.
}
