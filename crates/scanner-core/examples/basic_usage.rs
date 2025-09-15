//! Basic usage example for the high-performance scanner-core
//! 
//! This example demonstrates how to use the refactored scanner with the new
//! producer-consumer architecture.

use scanner_core::{Config, PatternRegistry, Scanner};
use std::path::PathBuf;
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    // Load pattern registry from TOML file
    let patterns_toml = r#"
        [version]
        schema = "1.0"
        updated = "2024-01-01"

        [[library]]
        name = "example-lib"
        languages = ["rust", "go", "java"]

        [library.patterns]
        import = ["use\\s+example_lib"]
        apis = ["example_lib::\\w+"]
    "#;

    let registry = PatternRegistry::load(patterns_toml)?;
    
    // Create configuration
    let config = Config {
        max_file_size: 2 * 1024 * 1024, // 2MB
        include_globs: vec![
            "**/*.rs".to_string(),
            "**/*.go".to_string(),
            "**/*.java".to_string(),
        ],
        exclude_globs: vec![],
        deterministic: true,
        progress_callback: Some(Arc::new(|processed, discovered, findings| {
            println!("Progress: {}/{} files processed, {} findings", processed, discovered, findings);
        })),
    };

    // Create scanner with empty detectors for this example
    let detectors = vec![];
    let scanner = Scanner::new(&registry, detectors, config);

    // Scan the current directory
    let roots = vec![PathBuf::from(".")];
    let findings = scanner.run(&roots)?;

    println!("Scan completed! Found {} findings", findings.len());
    for finding in findings.iter().take(5) {  // Show first 5 findings
        println!("  {} in {:?} at line {}", 
                 finding.library, 
                 finding.file, 
                 finding.span.line);
    }

    Ok(())
}