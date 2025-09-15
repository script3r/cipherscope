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
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    base.push(format!("cipherscope_test_{}_{}_{}", prefix, pid, ts));
    fs::create_dir_all(&base).unwrap();
    base
}

#[test]
fn tink_requires_import_and_api() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let patterns_path = workspace.join("patterns.toml");
    let patterns = fs::read_to_string(patterns_path).unwrap();
    let reg = Arc::new(PatternRegistry::load(&patterns).unwrap());
    let dets: Vec<Box<dyn Detector>> = vec![Box::new(PatternDetector::new(
        "detector-java",
        &[Language::Java],
        reg.clone(),
    ))];
    let scanner = Scanner::new(&reg, dets, Config::default());

    // 1) Import only: should NOT report Tink
    let dir_import_only = tmp_dir("tink_import_only");
    write_file(
        &dir_import_only,
        "src/ImportOnly.java",
        r#"package test;
import com.google.crypto.tink.aead.AeadConfig; // import present
public class ImportOnly {
    public static void main(String[] args) { System.out.println("hello"); }
}
"#,
    );
    let findings = scanner.run(std::slice::from_ref(&dir_import_only)).unwrap();
    assert!(
        !findings.iter().any(|f| f.library == "Google Tink (Java)"),
        "Tink should not be reported with import only"
    );

    // 2) API only: should NOT report Tink
    let dir_api_only = tmp_dir("tink_api_only");
    write_file(
        &dir_api_only,
        "src/ApiOnly.java",
        r#"package test;
public class ApiOnly {
    public static void main(String[] args) {
        // Mention API symbol without import
        String s = "Aead Mac HybridEncrypt"; // matches pattern by word, but no import
        System.out.println(s);
    }
}
"#,
    );
    let findings = scanner.run(std::slice::from_ref(&dir_api_only)).unwrap();
    assert!(
        !findings.iter().any(|f| f.library == "Google Tink (Java)"),
        "Tink should not be reported with API mentions only"
    );

    // 3) Import + API: should report Tink
    let dir_both = tmp_dir("tink_both");
    write_file(
        &dir_both,
        "src/Both.java",
        r#"package test;
import com.google.crypto.tink.aead.AeadConfig; // import present
public class Both {
    public static void main(String[] args) {
        // Include an API token
        String s = "Aead";
        System.out.println(s);
    }
}
"#,
    );
    let findings = scanner.run(std::slice::from_ref(&dir_both)).unwrap();
    assert!(
        findings.iter().any(|f| f.library == "Google Tink (Java)"),
        "Tink should be reported when import and API are present"
    );
}
