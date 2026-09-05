use cipherscope::{patterns::Language, scan::language_from_path};
use std::path::Path;

#[test]
fn extensions_select_enabled_grammars() {
    for (extension, language) in [
        ("PY", Language::Python),
        ("JsX", Language::JavaScript),
        ("TS", Language::TypeScript),
        ("TSX", Language::Tsx),
        ("c", Language::C),
        ("C", Language::Cpp),
    ] {
        assert_eq!(
            language_from_path(Path::new(&format!("source.{extension}"))),
            language.is_enabled().then_some(language),
        );
    }
}

#[cfg(feature = "lang-python")]
#[test]
fn directory_discovery_accepts_uppercase_extensions() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("source.PY"), "import cryptography\n").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cipherscope"))
        .arg("--roots")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("PyCA cryptography"));
}

#[cfg(feature = "lang-typescript")]
#[test]
fn tsx_uses_jsx_grammar_and_typescript_patterns() {
    let source = "import { createHash } from 'node:crypto';\nexport const View = () => <div>{createHash('sha256').digest('hex')}</div>;\n";
    let tree = cipherscope::scan::parse(Language::Tsx, source).unwrap();
    assert!(
        !tree.root_node().has_error(),
        "{}",
        tree.root_node().to_sexp()
    );
    let findings = cipherscope::scan_snippet(source, Language::Tsx, "source.tsx").unwrap();
    assert!(findings.iter().any(|hit| hit.identifier == "SHA-256"));
    assert!(findings.iter().any(|hit| hit.asset_type == "library"));

    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("source.tsx"), source).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cipherscope"))
        .arg("--roots")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("SHA-256"));
}

#[cfg(feature = "lang-typescript")]
#[test]
fn ordinary_typescript_retains_angle_bracket_type_assertions() {
    let tree =
        cipherscope::scan::parse(Language::TypeScript, "const value = <string>input;\n").unwrap();
    assert!(!tree.root_node().has_error());
}
