use std::{fs, process::Command};
use tempfile::TempDir;

fn scanner() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cipherscope"))
}

#[test]
fn successful_scan_replaces_existing_output() {
    let dir = TempDir::new().unwrap();
    let output_path = dir.path().join("inventory.jsonl");
    fs::write(&output_path, "previous inventory\n").unwrap();
    let output = scanner()
        .arg("--roots")
        .arg(dir.path())
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fs::read(output_path).unwrap().is_empty());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn missing_root_fails_and_preserves_existing_output() {
    let dir = TempDir::new().unwrap();
    let output_path = dir.path().join("inventory.jsonl");
    fs::write(&output_path, "previous inventory\n").unwrap();
    let output = scanner()
        .arg("--roots")
        .arg(dir.path().join("missing"))
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("scan incomplete"));
    assert_eq!(
        fs::read_to_string(output_path).unwrap(),
        "previous inventory\n"
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn invalid_exclusion_preserves_output() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("inventory.jsonl");
    fs::write(&path, "previous inventory").unwrap();
    let output = scanner()
        .arg("--roots")
        .arg(dir.path())
        .args(["--exclude", "["])
        .arg("--output")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(path).unwrap(), "previous inventory");
}

#[test]
fn output_cannot_replace_an_explicit_input() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("input.rs");
    let source = "use ring::digest;\n";
    fs::write(&path, source).unwrap();
    let output = scanner()
        .arg("--roots")
        .arg(&path)
        .arg("--output")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite scan input"));
    assert_eq!(fs::read_to_string(path).unwrap(), source);
}

#[test]
fn output_cannot_replace_custom_patterns() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("custom.toml");
    let patterns = "library = []\n";
    fs::write(&path, patterns).unwrap();
    let output = scanner()
        .arg("--roots")
        .arg(dir.path())
        .arg("--patterns")
        .arg(&path)
        .arg("--output")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(path).unwrap(), patterns);
}

#[cfg(feature = "lang-c")]
#[test]
fn failed_scan_still_streams_successful_findings_to_stdout() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("source.c"), "#include <openssl/evp.h>\n").unwrap();
    let output = scanner()
        .arg("--roots")
        .arg(dir.path())
        .arg("--roots")
        .arg(dir.path().join("missing"))
        .args(["--threads", "1"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("OpenSSL"));
}

#[cfg(unix)]
#[test]
fn output_symlink_does_not_modify_its_target() {
    let dir = TempDir::new().unwrap();
    let source = dir.path().join("source.rs");
    let output_path = dir.path().join("output.jsonl");
    fs::write(&source, "source text").unwrap();
    std::os::unix::fs::symlink(&source, &output_path).unwrap();
    let output = scanner()
        .arg("--roots")
        .arg(dir.path())
        .arg("--output")
        .arg(output_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(source).unwrap(), "source text");
}
