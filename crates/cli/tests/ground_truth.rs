use scanner_core::*;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

fn normalize(v: &mut Value) {
    match v {
        Value::Object(map) => {
            map.remove("serialNumber");
            if let Some(meta) = map.get_mut("metadata") {
                if let Some(obj) = meta.as_object_mut() {
                    obj.remove("timestamp");
                    obj.remove("component");
                }
            }
            // Dependencies removed from schema
            map.remove("dependencies");
            if let Some(Value::Array(assets)) = map.get_mut("cryptoAssets") {
                for a in assets.iter_mut() {
                    if let Some(obj) = a.as_object_mut() {
                        obj.remove("bom-ref");

                        // Normalize file paths in evidence to be relative
                        if let Some(Value::Object(evidence)) = obj.get_mut("evidence") {
                            if let Some(Value::String(file_path)) = evidence.get_mut("file") {
                                // Convert absolute paths to relative by removing the prefix
                                if file_path.contains("/fixtures/") {
                                    if let Some(idx) = file_path.find("/fixtures/") {
                                        *file_path = format!("fixtures/{}", &file_path[idx + 10..]);
                                    }
                                }
                            }
                        }
                    }
                }
                // Sort assets by name, sourceLibrary, then assetType for stable comparisons
                assets.sort_by(|a, b| {
                    let an = a.get("name").and_then(|x| x.as_str()).unwrap_or("");
                    let as_ = a
                        .get("sourceLibrary")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    let at = a.get("assetType").and_then(|x| x.as_str()).unwrap_or("");
                    let bn = b.get("name").and_then(|x| x.as_str()).unwrap_or("");
                    let bs = b
                        .get("sourceLibrary")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    let bt = b.get("assetType").and_then(|x| x.as_str()).unwrap_or("");
                    (an, as_, at).cmp(&(bn, bs, bt))
                });
            }
            for val in map.values_mut() {
                normalize(val);
            }
        }
        Value::Array(arr) => {
            for val in arr.iter_mut() {
                normalize(val);
            }
        }
        _ => {}
    }
}

#[test]
fn compare_comprehensive_ground_truth() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let patterns_path = workspace.join("patterns.toml");
    let patterns = fs::read_to_string(patterns_path).unwrap();
    let reg = Arc::new(PatternRegistry::load(&patterns).unwrap());

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

    let fixtures_root = workspace.join("fixtures");

    // iterate comprehensive subdirectories only
    let mut roots: Vec<PathBuf> = Vec::new();
    for lang_dir in fs::read_dir(&fixtures_root).unwrap() {
        let lang_dir = lang_dir.unwrap().path();
        let comp = lang_dir.join("comprehensive");
        if comp.exists() {
            roots.push(comp);
        }
    }

    let findings = scanner.run(&roots).unwrap();

    // Generate CBOM per root and compare if mv-cbom.json exists
    let gen = cbom_generator::CbomGenerator::with_registry(reg.clone());
    for root in roots {
        // Filter findings to this root, matching CLI single-project behavior
        let project_findings: Vec<Finding> = findings
            .iter()
            .filter(|f| f.file.starts_with(&root))
            .cloned()
            .collect();
        let cbom = gen.generate_cbom(&root, &project_findings).unwrap();
        let got = serde_json::to_value(&cbom).unwrap();
        let mut got_norm = got.clone();
        normalize(&mut got_norm);

        let truth_path = root.join("mv-cbom.json");
        if truth_path.exists() {
            let truth_s = fs::read_to_string(&truth_path).unwrap();
            let mut truth_v: Value = serde_json::from_str(&truth_s).unwrap();
            normalize(&mut truth_v);
            assert_eq!(
                got_norm,
                truth_v,
                "ground truth mismatch for {}",
                root.display()
            );
        }
    }
}
