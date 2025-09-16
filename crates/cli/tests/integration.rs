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

#[test]
fn scan_nested_general_fixtures() {
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
        Box::new(PatternDetector::new(
            "detector-swift",
            &[Language::Swift],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-objc",
            &[Language::ObjC],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-kotlin",
            &[Language::Kotlin],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-erlang",
            &[Language::Erlang],
            reg.clone(),
        )),
    ];
    let scanner = Scanner::new(&reg, dets, Config::default());

    // Scan the nested general fixtures root; test should not rely on per-file targets
    let root = workspace.join("fixtures/general");
    let findings = scanner.run(std::slice::from_ref(&root)).unwrap();

    // Assert we discovered at least one finding per intended language subdir
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
    let has_php = findings.iter().any(|f| matches!(f.language, Language::Php));
    let has_swift = findings
        .iter()
        .any(|f| matches!(f.language, Language::Swift));
    let has_objc = findings
        .iter()
        .any(|f| matches!(f.language, Language::ObjC));
    let has_kotlin = findings
        .iter()
        .any(|f| matches!(f.language, Language::Kotlin));
    let has_erlang = findings
        .iter()
        .any(|f| matches!(f.language, Language::Erlang));

    assert!(has_rust, "missing Rust findings in nested scan");
    assert!(has_python, "missing Python findings in nested scan");
    assert!(has_java, "missing Java findings in nested scan");
    assert!(has_c || has_cpp, "missing C/C++ findings in nested scan");
    assert!(has_go, "missing Go findings in nested scan");
    assert!(has_php, "missing PHP findings in nested scan");
    assert!(has_swift, "missing Swift findings in nested scan");
    assert!(has_objc, "missing ObjC findings in nested scan");
    assert!(has_kotlin, "missing Kotlin findings in nested scan");
    assert!(has_erlang, "missing Erlang findings in nested scan");

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
