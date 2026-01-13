use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::{NamedTempFile, TempDir};

fn normalize_path_in_value(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = v.as_object_mut()
        && let Some(path_val) = obj.get_mut("path")
    {
        *path_val = serde_json::Value::String("FIXME".to_string());
    }
    v
}

fn canonicalize_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut new = serde_json::Map::new();
            for k in keys {
                new.insert(k.clone(), canonicalize_value(map.get(&k).unwrap().clone()));
            }
            serde_json::Value::Object(new)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(canonicalize_value).collect())
        }
        _ => v,
    }
}

fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
    let s = fs::read_to_string(path).unwrap();
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| normalize_path_in_value(serde_json::from_str::<serde_json::Value>(l).unwrap()))
        .map(canonicalize_value)
        .collect()
}

fn should_skip_family(family: &str) -> bool {
    match family {
        "python" => !cfg!(feature = "lang-python"),
        "java" => !cfg!(feature = "lang-java"),
        "go" | "golang" => !cfg!(feature = "lang-go"),
        "swift" => !cfg!(feature = "lang-swift"),
        "php" => !cfg!(feature = "lang-php"),
        "objc" | "objective-c" => !cfg!(feature = "lang-objc"),
        "javascript" | "js" => !cfg!(feature = "lang-javascript"),
        "typescript" | "ts" => !cfg!(feature = "lang-typescript"),
        _ => false,
    }
}

#[test]
fn fixtures_match_ground_truth() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_dir = repo_root.join("fixtures");
    assert!(fixtures_dir.is_dir(), "fixtures directory missing");

    // Recursively collect case directories containing src/ and expected.jsonl
    fn collect_cases(dir: &Path, acc: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                let src = path.join("src");
                let expected = path.join("expected.jsonl");
                if src.is_dir() && expected.exists() {
                    acc.push(path.clone());
                }
                collect_cases(&path, acc);
            }
        }
    }

    let mut cases = Vec::new();
    collect_cases(&fixtures_dir, &mut cases);

    for case_dir in cases {
        let relative = case_dir.strip_prefix(&fixtures_dir).unwrap();
        let family = relative
            .components()
            .next()
            .unwrap()
            .as_os_str()
            .to_string_lossy();
        if should_skip_family(&family) {
            continue;
        }

        let src_dir = case_dir.join("src");
        let expected_path = case_dir.join("expected.jsonl");

        let tmp_out = NamedTempFile::new().unwrap();
        let out_path = tmp_out.path().to_path_buf();

        let status = Command::new(env!("CARGO_BIN_EXE_cipherscope"))
            .current_dir(&repo_root)
            .args([
                "--roots",
                src_dir.to_str().unwrap(),
                "--patterns",
                repo_root.join("patterns.toml").to_str().unwrap(),
                "--output",
                out_path.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "scanner failed for {}",
            case_dir.display()
        );

        let mut expected = read_jsonl(&expected_path);
        let mut actual = read_jsonl(&out_path);

        expected.sort_by_key(|a| a.to_string());
        actual.sort_by_key(|a| a.to_string());

        assert_eq!(
            actual,
            expected,
            "mismatch for fixture {}",
            case_dir.display()
        );
    }
}

#[test]
fn exclude_works() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_dir = repo_root.join("fixtures");

    let tmp_out = NamedTempFile::new().unwrap();
    let out_path = tmp_out.path().to_path_buf();

    // We'll scan the whole fixtures/go directory, but exclude the tink_aesgcm subdirectory
    let status = Command::new(env!("CARGO_BIN_EXE_cipherscope"))
        .current_dir(&repo_root)
        .args([
            "--roots",
            fixtures_dir.join("go").to_str().unwrap(),
            "--exclude",
            "**/tink_aesgcm/**",
            "--patterns",
            repo_root.join("patterns.toml").to_str().unwrap(),
            "--output",
            out_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "scanner failed for exclude_works");

    let mut expected = read_jsonl(&fixtures_dir.join("go/std_aesgcm/expected.jsonl"));
    let mut other_expected =
        read_jsonl(&fixtures_dir.join("go/crypto_comprehensive/expected.jsonl"));
    expected.append(&mut other_expected);

    let mut actual = read_jsonl(&out_path);

    expected.sort_by_key(|a| a.to_string());
    actual.sort_by_key(|a| a.to_string());

    assert!(!actual.is_empty());
    assert_eq!(actual, expected);
}

#[test]
fn multiple_roots_work() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures_dir = repo_root.join("fixtures");

    let tmp_out = NamedTempFile::new().unwrap();
    let out_path = tmp_out.path().to_path_buf();

    // We'll scan two directories and check for combined output
    let status = Command::new(env!("CARGO_BIN_EXE_cipherscope"))
        .current_dir(&repo_root)
        .args([
            "--roots",
            fixtures_dir.join("go/std_aesgcm/src").to_str().unwrap(),
            "--roots",
            fixtures_dir.join("go/tink_aesgcm/src").to_str().unwrap(),
            "--patterns",
            repo_root.join("patterns.toml").to_str().unwrap(),
            "--output",
            out_path.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "scanner failed for multiple_roots_work");

    let mut expected1 = read_jsonl(&fixtures_dir.join("go/std_aesgcm/expected.jsonl"));
    let mut expected2 = read_jsonl(&fixtures_dir.join("go/tink_aesgcm/expected.jsonl"));
    expected1.append(&mut expected2);

    let mut actual = read_jsonl(&out_path);

    expected1.sort_by_key(|a| a.to_string());
    actual.sort_by_key(|a| a.to_string());

    assert!(!actual.is_empty());
    assert_eq!(actual, expected1);
}

#[test]
fn max_file_mb_skips_large_files() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tmp_dir = TempDir::new().unwrap();
    let root = tmp_dir.path();

    let patterns_path = root.join("patterns.toml");
    fs::write(
        &patterns_path,
        r#"
[[library]]
name = "TestLib"
languages = ["Rust"]
[library.patterns]
include = ["TestLib"]
apis = ["TestLib"]

[[library.algorithms]]
name = "TEST-ALG"
symbol_patterns = ["test_algo"]
"#,
    )
    .unwrap();

    let small_path = root.join("small.rs");
    fs::write(&small_path, "use TestLib;\nfn main() { test_algo(); }\n").unwrap();

    let big_path = root.join("big.rs");
    let mut big_content = String::from("use TestLib;\nfn main() { test_algo(); }\n");
    big_content.push_str(&"a".repeat(1024 * 1024));
    fs::write(&big_path, big_content).unwrap();

    let tmp_out = NamedTempFile::new().unwrap();
    let out_path = tmp_out.path().to_path_buf();

    let status = Command::new(env!("CARGO_BIN_EXE_cipherscope"))
        .current_dir(&repo_root)
        .args([
            "--roots",
            root.to_str().unwrap(),
            "--patterns",
            patterns_path.to_str().unwrap(),
            "--output",
            out_path.to_str().unwrap(),
            "--max-file-mb",
            "1",
        ])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "scanner failed for max_file_mb_skips_large_files"
    );

    let output = fs::read_to_string(&out_path).unwrap();
    let mut paths = Vec::new();
    for line in output.lines().filter(|l| !l.trim().is_empty()) {
        let val: serde_json::Value = serde_json::from_str(line).unwrap();
        let path = val
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        paths.push(path);
    }
    assert!(!paths.is_empty());
    assert!(paths.iter().all(|p| p.ends_with("small.rs")));
}

#[test]
fn javascript_extension_detection() {
    // This test verifies JavaScript support is available
    // by checking that the feature flag is enabled
    #[cfg(not(feature = "lang-javascript"))]
    compile_error!("lang-javascript feature must be enabled");
}

#[test]
fn typescript_extension_detection() {
    // This test verifies TypeScript support is available
    // by checking that the feature flag is enabled
    #[cfg(not(feature = "lang-typescript"))]
    compile_error!("lang-typescript feature must be enabled");
}
