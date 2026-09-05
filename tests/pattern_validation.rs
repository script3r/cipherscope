use cipherscope::{DEFAULT_PATTERNS, patterns::PatternSet};

fn error(text: &str) -> String {
    format!("{:#}", PatternSet::from_toml(text).unwrap_err())
}

#[test]
fn bundled_catalog_remains_valid() {
    assert!(
        !PatternSet::from_toml(DEFAULT_PATTERNS)
            .unwrap()
            .libraries
            .is_empty()
    );
}

#[test]
fn rejects_unknown_fields_at_each_schema_level() {
    for text in [
        "libary = []",
        "[version]\nschmea = '1'",
        "[[library]]\nname = 'Test'\nlanguages = ['Python']\nalgoritms = []",
        "[[library]]\nname = 'Test'\nlanguages = ['Python']\n[library.patterns]\ninlcude = ['test']",
        "[[library]]\nname = 'Test'\nlanguages = ['Python']\n[[library.algorithms]]\nname = 'Test'\nsymbol_paterns = ['test']",
        "[[library]]\nname = 'Test'\nlanguages = ['Python']\n[[library.algorithms]]\nname = 'Test'\n[[library.algorithms.parameter_patterns]]\nname = 'size'\npattern = '(256)'\ndefault = 256",
    ] {
        assert!(error(text).contains("unknown field"), "{text}");
    }
}

#[test]
fn rejects_unknown_languages_including_partially_valid_lists() {
    for languages in ["['Pythno']", "['Python', 'Pythno']"] {
        let message = error(&format!(
            "[[library]]\nname = 'Test'\nlanguages = {languages}"
        ));
        assert!(message.contains("unknown language \"Pythno\""));
        assert!(message.contains("Test"));
    }
}

#[test]
fn rejects_unsupported_schema_versions() {
    assert!(error("[version]\nschema = '2'").contains("unsupported pattern schema"));
    assert!(PatternSet::from_toml("library = []").is_ok());
    assert!(PatternSet::from_toml("[version]\nschema = '1'").is_ok());
}

#[test]
fn reserved_languages_remain_accepted_but_inactive() {
    let patterns =
        PatternSet::from_toml("[[library]]\nname = 'Future'\nlanguages = ['Kotlin', 'Erlang']")
            .unwrap();
    assert!(patterns.libraries.is_empty());
    assert!(error("[[library]]\nname = 'Future'\nlanguages = ['Kotlin']\n[library.patterns]\ninclude = ['[']").contains("invalid include regex"));
}

#[test]
fn regex_errors_identify_the_library_algorithm_and_parameter() {
    let message = error(
        "[[library]]\nname = 'TestLib'\nlanguages = ['Python']\n[[library.algorithms]]\nname = 'TestAlg'\n[[library.algorithms.parameter_patterns]]\nname = 'keySize'\npattern = '['",
    );
    for expected in ["TestLib", "TestAlg", "keySize", "unclosed character class"] {
        assert!(message.contains(expected), "{message}");
    }
}

#[test]
fn rejects_empty_names_and_language_lists() {
    for text in [
        "[[library]]\nname = ' '\nlanguages = ['Python']",
        "[[library]]\nname = 'Test'\nlanguages = []",
        "[[library]]\nname = 'Test'\nlanguages = ['Python']\n[[library.algorithms]]\nname = ''",
        "[[library]]\nname = 'Test'\nlanguages = ['Python']\n[[library.algorithms]]\nname = 'Test'\n[[library.algorithms.parameter_patterns]]\nname = ''\npattern = '(256)'",
    ] {
        assert!(error(text).contains("must not be empty"));
    }
}
