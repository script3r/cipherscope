use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use indicatif::{ProgressBar, ProgressStyle};
use scanner_core::*;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "cipherscope")]
#[command(version, about = "Fast static scanner for third-party crypto libraries", long_about = None)]
struct Args {
    /// Paths to scan
    #[arg(value_name = "PATH", default_value = ".")]
    paths: Vec<PathBuf>,

    /// Emit JSONL to stdout
    #[arg(long, action = ArgAction::SetTrue)]
    json: bool,

    /// Write SARIF to file
    #[arg(long, value_name = "FILE")]
    sarif: Option<PathBuf>,

    /// Minimum confidence required
    #[arg(long, value_name = "FLOAT")]
    min_confidence: Option<f32>,

    /// Number of threads
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Maximum file size in MB
    #[arg(long, value_name = "MB")]
    max_file_size: Option<usize>,

    /// Include glob(s)
    #[arg(long, value_name = "GLOB")]
    include_glob: Vec<String>,

    /// Exclude glob(s)
    #[arg(long, value_name = "GLOB")]
    exclude_glob: Vec<String>,

    /// Allow only these libraries
    #[arg(long, value_name = "LIB")]
    allow: Vec<String>,

    /// Deny these libraries
    #[arg(long, value_name = "LIB")]
    deny: Vec<String>,

    /// Deterministic output ordering
    #[arg(long, action = ArgAction::SetTrue)]
    deterministic: bool,

    /// Fail with code 2 if findings are present
    #[arg(long, action = ArgAction::SetTrue)]
    fail_on_find: bool,

    /// Print merged patterns/config and exit
    #[arg(long, action = ArgAction::SetTrue)]
    print_config: bool,

    /// Dry-run: list files that would be scanned
    #[arg(long, action = ArgAction::SetTrue)]
    dry_run: bool,

    /// Path to patterns file
    #[arg(long, value_name = "FILE", default_value = "patterns.toml")]
    patterns: PathBuf,

    /// Show progress bar during scanning
    #[arg(long, action = ArgAction::SetTrue)]
    progress: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(n) = args.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .ok();
    }

    // Load patterns from specified file
    let base = fs::read_to_string(&args.patterns)
        .with_context(|| format!("read patterns file: {}", args.patterns.display()))?;
    let reg = PatternRegistry::load(&base)?;
    let reg = Arc::new(reg);

    if args.print_config {
        println!("{}", base);
        return Ok(());
    }

    // Prepare detectors
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

    let mut cfg = Config {
        min_confidence: args.min_confidence,
        include_globs: args.include_glob.clone(),
        exclude_globs: args.exclude_glob.clone(),
        allow_libs: args.allow.clone(),
        deny_libs: args.deny.clone(),
        deterministic: args.deterministic,
        ..Default::default()
    };
    if let Some(mb) = args.max_file_size {
        cfg.max_file_size = mb * 1024 * 1024;
    }

    // Set up progress reporting if requested
    if args.progress {
        let pb = ProgressBar::new(0);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({percent}%) | {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_message("Scanning files...");

        cfg.progress_callback = Some(Arc::new(move |processed, total, findings| {
            pb.set_length(total as u64);
            pb.set_position(processed as u64);
            pb.set_message(format!("Found {} findings", findings));
        }));
    }

    let scanner = Scanner::new(&reg, dets, cfg);
    if args.dry_run {
        let files = scanner.discover_files(&args.paths);
        for p in files {
            println!("{}", p.display());
        }
        return Ok(());
    }

    let findings = scanner.run(&args.paths)?;

    // Clear progress bar if it was shown
    if args.progress {
        println!(); // Move to next line after progress bar
    }

    if args.json {
        for f in &findings {
            println!("{}", serde_json::to_string(f)?);
        }
    } else {
        print_table(&findings);
    }

    if let Some(sarif_path) = args.sarif.as_ref() {
        let sarif = to_sarif(&findings);
        fs::write(sarif_path, serde_json::to_vec_pretty(&sarif)?)?;
    }

    if args.fail_on_find && !findings.is_empty() {
        std::process::exit(2);
    }
    Ok(())
}

fn print_table(findings: &[Finding]) {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<(Language, String), Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        map.entry((f.language, f.library.clone()))
            .or_default()
            .push(f);
    }
    println!("Language | Library | Count | Example");
    println!("---------|---------|-------|--------");
    for ((lang, lib), list) in map {
        let ex = list
            .first()
            .map(|f| format!("{}:{} {}", f.file.display(), f.span.line, f.symbol))
            .unwrap_or_default();
        println!("{:?} | {} | {} | {}", lang, lib, list.len(), ex);
    }
}

#[derive(serde::Serialize)]
struct SarifLog {
    version: String,
    #[serde(rename = "$schema")]
    schema: String,
    runs: Vec<SarifRun>,
}
#[derive(serde::Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}
#[derive(serde::Serialize)]
struct SarifTool {
    driver: SarifDriver,
}
#[derive(serde::Serialize)]
struct SarifDriver {
    name: String,
    version: String,
}
#[derive(serde::Serialize)]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}
#[derive(serde::Serialize)]
struct SarifMessage {
    text: String,
}
#[derive(serde::Serialize)]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}
#[derive(serde::Serialize)]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}
#[derive(serde::Serialize)]
struct SarifArtifactLocation {
    uri: String,
}
#[derive(serde::Serialize)]
struct SarifRegion {
    start_line: usize,
    start_column: usize,
}

fn to_sarif(findings: &[Finding]) -> SarifLog {
    SarifLog {
        version: "2.1.0".into(),
        schema: "https://json.schemastore.org/sarif-2.1.0.json".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "cryptofind".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                },
            },
            results: findings
                .iter()
                .map(|f| SarifResult {
                    rule_id: f.detector_id.clone(),
                    level: "note".into(),
                    message: SarifMessage {
                        text: format!("{} in {:?}", f.library, f.language),
                    },
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation {
                                uri: f.file.display().to_string(),
                            },
                            region: SarifRegion {
                                start_line: f.span.line,
                                start_column: f.span.column,
                            },
                        },
                    }],
                })
                .collect(),
        }],
    }
}
