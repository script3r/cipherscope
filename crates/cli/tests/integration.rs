use scanner_core::*;
use std::path::PathBuf;

#[test]
fn scan_fixtures() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    
    // Load patterns for AST-based detectors
    let patterns_path = workspace.join("patterns.toml");
    let patterns_content = std::fs::read_to_string(patterns_path).unwrap();
    let registry = std::sync::Arc::new(PatternRegistry::load(&patterns_content).unwrap());
    
    // Use AST-based detectors
    let dets: Vec<Box<dyn Detector>> = vec![
        Box::new(AstBasedDetector::new(
            "ast-detector-c",
            &[Language::C],
            registry.clone(),
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-cpp",
            &[Language::Cpp],
            registry.clone(),
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-rust",
            &[Language::Rust],
            registry.clone(),
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-python",
            &[Language::Python],
            registry.clone(),
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-java",
            &[Language::Java],
            registry.clone(),
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-go",
            &[Language::Go],
            registry.clone(),
        ).unwrap()),
    ];
    
    let scanner = Scanner::new(&registry, dets, Config::default());
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

    // Expect at least one hit per language category across AST-supported languages
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

    assert!(has_rust, "missing Rust findings");
    assert!(has_python, "missing Python findings");
    assert!(has_java, "missing Java findings");
    assert!(has_c, "missing C/C++ findings");
    assert!(has_go, "missing Go findings");

    // Note: legacy negative fixtures removed; comprehensive fixtures are used now.
}

#[test]
fn scan_nested_general_fixtures() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    
    // Load patterns for AST-based detectors
    let patterns_path = workspace.join("patterns.toml");
    let patterns_content = std::fs::read_to_string(patterns_path).unwrap();
    let registry = std::sync::Arc::new(PatternRegistry::load(&patterns_content).unwrap());
    
    // Use AST-based detectors
    let dets: Vec<Box<dyn Detector>> = vec![
        Box::new(AstBasedDetector::new(
            "ast-detector-c",
            &[Language::C],
            registry.clone(),
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-cpp",
            &[Language::Cpp],
            registry.clone(),
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-rust",
            &[Language::Rust],
            registry.clone(),
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-python",
            &[Language::Python],
            registry.clone(),
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-java",
            &[Language::Java],
            registry.clone(),
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-go",
            &[Language::Go],
            registry.clone(),
        ).unwrap()),
    ];
    
    let scanner = Scanner::new(&registry, dets, Config::default());

    // Scan the nested general fixtures root; test should not rely on per-file targets
    let root = workspace.join("fixtures/general");
    let findings = scanner.run(std::slice::from_ref(&root)).unwrap();

    // Assert we discovered at least one finding per AST-supported language subdir
    let has_rust = findings
        .iter()
        .any(|f| matches!(f.language, Language::Rust));
    let has_python = findings
        .iter()
        .any(|f| matches!(f.language, Language::Python));
    let has_java = findings
        .iter()
        .any(|f| matches!(f.language, Language::Java));
    let has_c = findings.iter().any(|f| matches!(f.language, Language::C));
    let has_cpp = findings.iter().any(|f| matches!(f.language, Language::Cpp));
    let has_go = findings.iter().any(|f| matches!(f.language, Language::Go));

    assert!(has_rust, "missing Rust findings in nested scan");
    assert!(has_python, "missing Python findings in nested scan");
    assert!(has_java, "missing Java findings in nested scan");
    assert!(has_c || has_cpp, "missing C/C++ findings in nested scan");
    assert!(has_go, "missing Go findings in nested scan");

    // Ensure deduplication does not erase per-language assets: group by (file, language)
    use std::collections::HashSet;
    let mut file_lang_pairs = HashSet::new();
    for f in &findings {
        file_lang_pairs.insert((f.file.display().to_string(), f.language));
    }
    // Expect multiple unique (file,language) pairs in nested scan
    assert!(
        file_lang_pairs.len() >= 5,
        "unexpectedly low unique file/language pairs"
    );
}
