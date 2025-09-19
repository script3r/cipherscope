use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use indicatif::{ProgressBar, ProgressStyle};
use scanner_core::{Config, Detector, Language, AstBasedDetector, Scanner, CryptoFindings};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "cipherscope")]
#[command(version, about = "AST-based cryptographic library and algorithm detection tool - outputs JSONL format", long_about = None)]
struct Args {
    /// Paths to scan
    #[arg(value_name = "PATH", default_value = ".")]
    paths: Vec<PathBuf>,

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

    /// Show progress bar during scanning
    #[arg(long, action = ArgAction::SetTrue)]
    progress: bool,

    /// Output file for JSONL results (default: stdout)
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(n) = args.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .ok();
    }

    // Prepare AST-based detectors for each language
    let dets: Vec<Box<dyn Detector>> = vec![
        Box::new(AstBasedDetector::new(
            "ast-detector-c",
            &[Language::C],
        ).with_context(|| "Failed to create C AST detector")?),
        Box::new(AstBasedDetector::new(
            "ast-detector-cpp",
            &[Language::Cpp],
        ).with_context(|| "Failed to create C++ AST detector")?),
        Box::new(AstBasedDetector::new(
            "ast-detector-rust",
            &[Language::Rust],
        ).with_context(|| "Failed to create Rust AST detector")?),
        Box::new(AstBasedDetector::new(
            "ast-detector-python",
            &[Language::Python],
        ).with_context(|| "Failed to create Python AST detector")?),
        Box::new(AstBasedDetector::new(
            "ast-detector-java",
            &[Language::Java],
        ).with_context(|| "Failed to create Java AST detector")?),
        Box::new(AstBasedDetector::new(
            "ast-detector-go",
            &[Language::Go],
        ).with_context(|| "Failed to create Go AST detector")?),
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

    // Create a dummy registry for the scanner (AST detectors don't use it)
    let dummy_registry = scanner_core::PatternRegistry::empty();
    let scanner = Scanner::new(&dummy_registry, dets, cfg);
    let findings = scanner.run(&args.paths)?;

    // Clear progress bar if it was shown
    if args.progress {
        println!(); // Move to next line after progress bar
    }

    // Convert scanner findings to crypto findings and output as JSONL
    let crypto_findings = CryptoFindings::from_scanner_findings(findings);
    let jsonl_output = crypto_findings.to_jsonl()
        .with_context(|| "Failed to serialize findings to JSONL")?;

    // Output results
    match &args.output {
        Some(output_file) => {
            fs::write(output_file, &jsonl_output)
                .with_context(|| format!("Failed to write JSONL to {}", output_file.display()))?;
            eprintln!("Found {} cryptographic findings written to {}", 
                     crypto_findings.len(), output_file.display());
        }
        None => {
            // Print JSONL to stdout
            println!("{}", jsonl_output);
        }
    }

    Ok(())
}
