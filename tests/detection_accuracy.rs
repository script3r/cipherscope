#[cfg(any(feature = "lang-c", feature = "lang-python"))]
use cipherscope::{patterns::Language, scan_snippet};

#[cfg(feature = "lang-c")]
#[test]
fn include_after_copyright_is_not_skipped_by_hint() {
    let findings = scan_snippet(
        "// Copyright\n#include <openssl/evp.h>\n",
        Language::C,
        "source.c",
    )
    .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].identifier, "OpenSSL");
    assert_eq!(findings[0].evidence.line, 2);
}

#[cfg(feature = "lang-c")]
#[test]
fn comments_do_not_create_algorithm_findings() {
    let findings = scan_snippet(
        "#include <openssl/evp.h>\n// EVP_aes_256_gcm();\n/* EVP_aes_128_cbc(); */\n",
        Language::C,
        "source.c",
    )
    .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].identifier, "OpenSSL");
}

#[cfg(feature = "lang-c")]
#[test]
fn comments_inside_calls_cannot_trigger_symbol_matches() {
    let findings = scan_snippet(
        "#include <openssl/evp.h>\nvoid f() { unrelated(/* EVP_aes_256_gcm() */); }\n",
        Language::C,
        "source.c",
    )
    .unwrap();
    assert_eq!(findings.len(), 1);
}

#[cfg(feature = "lang-python")]
#[test]
fn api_only_library_cannot_be_anchored_by_a_comment() {
    let patterns = cipherscope::patterns::PatternSet::from_toml(
        r#"
[[library]]
name = "TestLib"
languages = ["Python"]
[library.patterns]
apis = ["CryptoLib"]
"#,
    )
    .unwrap();
    let findings = cipherscope::scan_with_patterns(
        "# CryptoLib.new()\npass\n",
        Language::Python,
        "source.py",
        &patterns,
    )
    .unwrap();
    assert!(findings.is_empty());
}

#[cfg(feature = "lang-python")]
#[test]
fn node_anchors_work_inside_indented_code_with_absolute_regex_anchors() {
    let patterns = cipherscope::patterns::PatternSet::from_toml(
        r#"
[[library]]
name = "TestLib"
languages = ["Python"]
[library.patterns]
include = ['\Aimport testlib\z']
"#,
    )
    .unwrap();
    let findings = cipherscope::scan_with_patterns(
        "def f():\n    import testlib\n    pass\n",
        Language::Python,
        "source.py",
        &patterns,
    )
    .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].evidence.line, 2);
    assert_eq!(findings[0].evidence.column, 5);
    assert!(!cipherscope::scan::has_anchor_hint(
        Language::Python,
        "print('hello')",
        &patterns,
    ));
}

#[cfg(feature = "lang-c")]
#[test]
fn comment_masking_preserves_unicode_byte_columns_and_real_calls() {
    let source = "#include <openssl/evp.h>\nvoid f() { /* café */ EVP_aes_256_gcm(); }\n";
    let findings = scan_snippet(source, Language::C, "source.c").unwrap();
    let hit = findings.iter().find(|f| f.identifier == "AES-GCM").unwrap();
    assert_eq!(hit.evidence.line, 2);
    assert_eq!(
        hit.evidence.column,
        source.lines().nth(1).unwrap().find("EVP").unwrap() + 1
    );
    assert_eq!(hit.metadata["keySize"], 256);
}

#[cfg(feature = "lang-c")]
#[test]
fn string_contents_are_preserved_when_masking_comments() {
    let patterns = cipherscope::patterns::PatternSet::from_toml(
        r#"
[[library]]
name = "TestLib"
languages = ["C"]
[library.patterns]
include = ['testlib.h']
[[library.algorithms]]
name = "TestAlgorithm"
symbol_patterns = ['https://example.test/crypto']
"#,
    )
    .unwrap();
    let findings = cipherscope::scan_with_patterns(
        "#include <testlib.h>\nvoid f() { call(\"https://example.test/crypto\"); }\n",
        Language::C,
        "source.c",
        &patterns,
    )
    .unwrap();
    assert!(findings.iter().any(|hit| hit.identifier == "TestAlgorithm"));
}
