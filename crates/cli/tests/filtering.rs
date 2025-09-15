use scanner_core::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_file(dir: &Path, rel: &str, contents: &str) {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, contents).unwrap();
}

fn tmp_dir(prefix: &str) -> PathBuf {
    let mut base = std::env::temp_dir();
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let pid = std::process::id();
    base.push(format!("cipherscope_test_{}_{}_{}", prefix, pid, ts));
    fs::create_dir_all(&base).unwrap();
    base
}

fn load_registry() -> Arc<PatternRegistry> {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let patterns_path = workspace.join("patterns.toml");
    let patterns = fs::read_to_string(patterns_path).unwrap();
    Arc::new(PatternRegistry::load(&patterns).unwrap())
}

#[test]
fn commented_import_does_not_trigger_anchor_java() {
    let reg = load_registry();
    let dets: Vec<Box<dyn Detector>> = vec![Box::new(PatternDetector::new(
        "detector-java",
        &[Language::Java],
        reg.clone(),
    ))];
    let cfg = Config::default();
    let scanner = Scanner::new(&reg, dets, cfg);

    let dir = tmp_dir("commented_import_java");
    write_file(
        &dir,
        "src/Main.java",
        r#"package test;
// import javax.crypto.Cipher;  // commented anchor
public class Main {
    public static void main(String[] args) throws Exception {
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding"); // API present
    }
}
"#,
    );
    let findings = scanner.run(std::slice::from_ref(&dir)).unwrap();
    assert!(
        !findings
            .iter()
            .any(|f| f.library == "Java JCA/JCE"),
        "JCA/JCE should not be reported when import is commented"
    );
}

#[test]
fn php_api_only_reports_openssl() {
    let reg = load_registry();
    let dets: Vec<Box<dyn Detector>> = vec![Box::new(PatternDetector::new(
        "detector-php",
        &[Language::Php],
        reg.clone(),
    ))];
    let cfg = Config::default();
    let scanner = Scanner::new(&reg, dets, cfg);

    let dir = tmp_dir("php_openssl_api_only");
    write_file(
        &dir,
        "web/index.php",
        r#"<?php
// No imports for PHP OpenSSL detector; API use is enough
$ciphertext = openssl_encrypt("data", "aes-256-cbc", "key", 0, "1234567890123456");
echo $ciphertext;
"#,
    );
    let findings = scanner.run(std::slice::from_ref(&dir)).unwrap();
    assert!(
        findings.iter().any(|f| f.library == "OpenSSL (PHP)"),
        "OpenSSL (PHP) should be reported on API use only"
    );
}

#[test]
fn include_glob_filters_file_types() {
    let reg = load_registry();
    let dets_java: Vec<Box<dyn Detector>> = vec![
        Box::new(PatternDetector::new("detector-java", &[Language::Java], reg.clone())),
        Box::new(PatternDetector::new("detector-php", &[Language::Php], reg.clone())),
    ];

    let dir = tmp_dir("include_glob_filters");
    // Java file with anchor+API
    write_file(
        &dir,
        "src/Main.java",
        r#"package test;
import java.security.MessageDigest;
public class Main {
    public static void main(String[] args) throws Exception {
        java.security.KeyFactory.getInstance("RSA");
    }
}
"#,
    );
    // PHP file with API
    write_file(
        &dir,
        "web/index.php",
        r#"<?php
echo openssl_encrypt("data", "aes-256-cbc", "key", 0, "1234567890123456");
"#,
    );

    // Only Java
    let cfg_java_only = Config {
        include_globs: vec!["**/*.java".to_string()],
        ..Default::default()
    };
    let scanner_java = Scanner::new(&reg, dets_java, cfg_java_only);
    let findings_java = scanner_java.run(std::slice::from_ref(&dir)).unwrap();
    assert!(findings_java.iter().any(|f| f.library == "Java JCA/JCE"));
    assert!(
        !findings_java.iter().any(|f| f.library == "OpenSSL (PHP)"),
        "PHP findings should be excluded by include_glob"
    );

    // Only PHP
    let cfg_php_only = Config {
        include_globs: vec!["**/*.php".to_string()],
        ..Default::default()
    };
    let dets_php: Vec<Box<dyn Detector>> = vec![
        Box::new(PatternDetector::new("detector-java", &[Language::Java], reg.clone())),
        Box::new(PatternDetector::new("detector-php", &[Language::Php], reg.clone())),
    ];
    let scanner_php = Scanner::new(&reg, dets_php, cfg_php_only);
    let findings_php = scanner_php.run(std::slice::from_ref(&dir)).unwrap();
    assert!(findings_php.iter().any(|f| f.library == "OpenSSL (PHP)"));
    assert!(
        !findings_php.iter().any(|f| f.library == "Java JCA/JCE"),
        "Java findings should be excluded by include_glob"
    );
}

#[test]
fn max_file_size_skips_large_files() {
    let reg = load_registry();
    let dets: Vec<Box<dyn Detector>> = vec![Box::new(PatternDetector::new(
        "detector-java",
        &[Language::Java],
        reg.clone(),
    ))];

    let dir = tmp_dir("max_file_size");
    // Create a large Java file that would otherwise match JCA
    let mut content = String::from(
        "package test;\nimport javax.crypto.Cipher;\npublic class Big { public static void main(String[] a){ } }\n",
    );
    // Append enough data to exceed threshold
    for _ in 0..5000 {
        content.push_str("// padding padding padding padding padding padding\n");
    }
    write_file(&dir, "src/Big.java", &content);

    let cfg_small_limit = Config {
        max_file_size: 512, // bytes
        ..Default::default()
    };
    let scanner = Scanner::new(&reg, dets, cfg_small_limit);
    let findings = scanner.run(std::slice::from_ref(&dir)).unwrap();
    assert!(findings.is_empty(), "Large file should be skipped by max_file_size");
}

