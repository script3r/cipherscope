use anyhow::{Context, Result};
use cbom_generator::CbomGenerator;
use clap::{ArgAction, Parser};
use indicatif::{ProgressBar, ProgressStyle};
use scanner_core::*;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "cipherscope")]
#[command(version, about = "Generate Cryptographic Bill of Materials (MV-CBOM) for Post-Quantum Cryptography readiness assessment", long_about = None)]
struct Args {
    /// Paths to scan
    #[arg(value_name = "PATH", default_value = ".")]
    paths: Vec<PathBuf>,

    /// Generate MV-CBOMs recursively for all discovered projects (default: single project)
    #[arg(long, action = ArgAction::SetTrue)]
    recursive: bool,

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

    /// Deterministic output ordering
    #[arg(long, action = ArgAction::SetTrue)]
    deterministic: bool,

    /// Print merged patterns/config and exit
    #[arg(long, action = ArgAction::SetTrue)]
    print_config: bool,

    /// Path to patterns file
    #[arg(long, value_name = "FILE", default_value = "patterns.toml")]
    patterns: PathBuf,

    /// Show progress bar during scanning
    #[arg(long, action = ArgAction::SetTrue)]
    progress: bool,

    /// Output file for single-project CBOM (default: stdout)
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output directory for recursive CBOMs (default: stdout JSON array)
    #[arg(long, value_name = "DIR")]
    output_dir: Option<PathBuf>,
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
        include_globs: args.include_glob.clone(),
        exclude_globs: args.exclude_glob.clone(),
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
    let findings = scanner.run(&args.paths)?;

    // Clear progress bar if it was shown
    if args.progress {
        println!(); // Move to next line after progress bar
    }

    // Generate MV-CBOM (always - this is the primary functionality)
    // Deterministic mode for tests/ground-truth when --deterministic is set
    let cbom_generator = if args.deterministic {
        CbomGenerator::with_registry_mode(reg.clone(), true)
    } else {
        CbomGenerator::with_registry(reg.clone())
    };

    // Use the first path as the scan root for CBOM generation
    let default_path = PathBuf::from(".");
    let scan_path = args.paths.first().unwrap_or(&default_path);

    if args.progress {
        eprintln!("Generating CBOM for {} findings...", findings.len());
    }

    if args.recursive {
        // Simplified: generate a single CBOM for the root
        match cbom_generator.generate_cboms_recursive(scan_path, &findings) {
            Ok(cboms) => {
                if let Some(dir) = &args.output_dir {
                    // Write each CBOM into the specified directory
                    if let Err(e) = fs::create_dir_all(dir) {
                        eprintln!("Failed to create output directory {}: {}", dir.display(), e);
                        std::process::exit(1);
                    }
                    for (i, (_project_path, cbom)) in cboms.iter().enumerate() {
                        let file = dir.join(format!("{:03}-mv-cbom.json", i + 1));
                        if let Err(e) = cbom_generator.write_cbom(cbom, &file) {
                            eprintln!("Failed to write MV-CBOM to {}: {}", file.display(), e);
                            std::process::exit(1);
                        }
                    }
                    println!("Generated {} MV-CBOMs to {}", cboms.len(), dir.display());
                } else {
                    // Print JSON array to stdout
                    let only_cboms: Vec<&cbom_generator::MvCbom> =
                        cboms.iter().map(|(_, c)| c).collect();
                    let json = serde_json::to_string_pretty(&only_cboms)
                        .expect("Failed to serialize MV-CBOMs to JSON");
                    println!("{}", json);
                }
            }
            Err(e) => {
                eprintln!("Failed to generate recursive MV-CBOMs: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Single CBOM generation
        match cbom_generator.generate_cbom(scan_path, &findings) {
            Ok(cbom) => {
                if let Some(path) = &args.output {
                    match cbom_generator.write_cbom(&cbom, path) {
                        Ok(()) => {
                            println!("MV-CBOM written to: {}", path.display());
                            println!("Found {} cryptographic assets", cbom.crypto_assets.len());
                            // Dependencies removed
                        }
                        Err(e) => {
                            eprintln!("Failed to write MV-CBOM: {}", e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    // Print JSON to stdout (no extra lines)
                    let json = serde_json::to_string_pretty(&cbom)
                        .expect("Failed to serialize MV-CBOM to JSON");
                    println!("{}", json);
                }
            }
            Err(e) => {
                eprintln!("Failed to generate MV-CBOM: {}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
