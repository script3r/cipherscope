//! Progress reporting tests to ensure accurate counting and prevent regression

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use scanner_core::{Config, PatternRegistry, Scanner};

/// Mock progress callback that captures all progress updates
#[derive(Debug, Default)]
struct ProgressCapture {
    updates: Arc<Mutex<Vec<(usize, usize, usize)>>>,
    final_counts: Arc<Mutex<Option<(usize, usize, usize)>>>,
}

impl ProgressCapture {
    fn new() -> Self {
        Self::default()
    }

    fn create_callback(&self) -> Arc<dyn Fn(usize, usize, usize) + Send + Sync> {
        let updates = self.updates.clone();
        let final_counts = self.final_counts.clone();

        Arc::new(move |processed, discovered, findings| {
            // Store all updates for analysis
            updates
                .lock()
                .unwrap()
                .push((processed, discovered, findings));

            // Store final counts (last update should be final)
            *final_counts.lock().unwrap() = Some((processed, discovered, findings));
        })
    }

    fn get_final_counts(&self) -> Option<(usize, usize, usize)> {
        *self.final_counts.lock().unwrap()
    }

    fn get_all_updates(&self) -> Vec<(usize, usize, usize)> {
        self.updates.lock().unwrap().clone()
    }
}

#[test]
fn test_progress_reporting_accuracy() {
    // Create simple test patterns that will match our fixture files
    let patterns_toml = r##"
[version]
schema = "1.0"
updated = "2024-01-01"

[[library]]
name = "test-lib"
languages = ["rust", "go", "java", "c", "cpp", "python"]

[library.patterns]
include = ["#include", "use ", "import "]
apis = ["printf", "println", "print", "main"]
    "##;

    let registry = PatternRegistry::load(patterns_toml).expect("Failed to load patterns");

    // Set up progress capture
    let progress_capture = ProgressCapture::new();

    let config = Config {
        max_file_size: 1024 * 1024, // 1MB
        include_globs: vec![
            "**/*.rs".to_string(),
            "**/*.go".to_string(),
            "**/*.java".to_string(),
            "**/*.c".to_string(),
            "**/*.cpp".to_string(),
            "**/*.py".to_string(),
        ],
        exclude_globs: vec![],
        deterministic: true,
        progress_callback: Some(progress_capture.create_callback()),
    };

    // Create scanner with empty detectors for this test
    let detectors = vec![];
    let scanner = Scanner::new(&registry, detectors, config);

    // Scan the fixtures directory (comprehensive fixtures layout)
    let fixtures_path = PathBuf::from("../../fixtures");
    let roots = vec![fixtures_path];

    // First, count the expected files using discover_files (dry run)
    let expected_files = scanner.discover_files(&roots);
    let expected_count = expected_files.len();

    // Run the actual scan with progress reporting
    let _findings = scanner.run(&roots).expect("Scan failed");

    // Verify progress reporting accuracy
    let final_counts = progress_capture
        .get_final_counts()
        .expect("No progress updates received");

    let (final_processed, final_discovered, _final_findings) = final_counts;

    // Core assertion: discovered count should match our dry-run count
    assert_eq!(
        final_discovered, expected_count,
        "Progress reported {} discovered files, but dry-run found {} files. This indicates a regression in progress counting.",
        final_discovered, expected_count
    );

    // Core assertion: processed count should equal discovered count
    // (all discovered files should be processed)
    assert_eq!(
        final_processed, final_discovered,
        "Progress reported {} processed files but {} discovered files. All discovered files should be processed.",
        final_processed, final_discovered
    );

    // Verify we actually found some files (fixtures should contain test files)
    assert!(
        final_discovered > 0,
        "No files were discovered. Check that fixtures directory exists and contains source files."
    );

    println!("✅ Progress reporting test passed:");
    println!("   Discovered: {} files", final_discovered);
    println!("   Processed:  {} files", final_processed);
    println!("   Expected:   {} files (from dry-run)", expected_count);
}

#[test]
fn test_progress_monotonic_increase() {
    // Test that progress counts only increase (never decrease)
    let patterns_toml = r##"
[version]
schema = "1.0"
updated = "2024-01-01"

[[library]]
name = "test-lib"
languages = ["rust"]

[library.patterns]
apis = ["main"]
    "##;

    let registry = PatternRegistry::load(patterns_toml).expect("Failed to load patterns");
    let progress_capture = ProgressCapture::new();

    let config = Config {
        max_file_size: 1024 * 1024,
        include_globs: vec!["**/*.rs".to_string()],
        exclude_globs: vec![],
        deterministic: true,
        progress_callback: Some(progress_capture.create_callback()),
    };

    let detectors = vec![];
    let scanner = Scanner::new(&registry, detectors, config);

    let fixtures_path = PathBuf::from("../../fixtures");
    let _findings = scanner.run(&[fixtures_path]).expect("Scan failed");

    // Verify that progress counts are monotonically increasing
    let all_updates = progress_capture.get_all_updates();

    let mut prev_processed = 0;
    let mut prev_discovered = 0;
    let mut prev_findings = 0;

    for (i, &(processed, discovered, findings)) in all_updates.iter().enumerate() {
        assert!(
            processed >= prev_processed,
            "Progress regression at update {}: processed count decreased from {} to {}",
            i,
            prev_processed,
            processed
        );

        assert!(
            discovered >= prev_discovered,
            "Progress regression at update {}: discovered count decreased from {} to {}",
            i,
            prev_discovered,
            discovered
        );

        assert!(
            findings >= prev_findings,
            "Progress regression at update {}: findings count decreased from {} to {}",
            i,
            prev_findings,
            findings
        );

        prev_processed = processed;
        prev_discovered = discovered;
        prev_findings = findings;
    }

    println!(
        "✅ Monotonic progress test passed with {} updates",
        all_updates.len()
    );
}

#[test]
fn test_progress_file_extension_accuracy() {
    // Test that progress counting respects file extension filtering
    let patterns_toml = r##"
[version]
schema = "1.0"
updated = "2024-01-01"

[[library]]
name = "rust-only-lib"
languages = ["rust"]

[library.patterns]
apis = ["main"]
    "##;

    let registry = PatternRegistry::load(patterns_toml).expect("Failed to load patterns");

    // Create two progress captures - one for Rust-only, one for all files
    let rust_only_capture = ProgressCapture::new();
    let all_files_capture = ProgressCapture::new();

    // Scan 1: Rust files only
    let rust_config = Config {
        max_file_size: 1024 * 1024,
        include_globs: vec!["**/*.rs".to_string()],
        exclude_globs: vec![],
        deterministic: true,
        progress_callback: Some(rust_only_capture.create_callback()),
    };

    let detectors1 = vec![];
    let rust_scanner = Scanner::new(&registry, detectors1, rust_config);
    let fixtures_path = PathBuf::from("../../fixtures");
    let _rust_findings = rust_scanner
        .run(std::slice::from_ref(&fixtures_path))
        .expect("Rust scan failed");

    // Scan 2: All supported file types
    let all_config = Config {
        max_file_size: 1024 * 1024,
        include_globs: vec![
            "**/*.rs".to_string(),
            "**/*.go".to_string(),
            "**/*.java".to_string(),
            "**/*.c".to_string(),
            "**/*.py".to_string(),
        ],
        exclude_globs: vec![],
        deterministic: true,
        progress_callback: Some(all_files_capture.create_callback()),
    };

    let detectors2 = vec![];
    let all_scanner = Scanner::new(&registry, detectors2, all_config);
    let _all_findings = all_scanner
        .run(&[fixtures_path])
        .expect("All files scan failed");

    let rust_counts = rust_only_capture.get_final_counts().unwrap();
    let all_counts = all_files_capture.get_final_counts().unwrap();

    let (_rust_processed, rust_discovered, _) = rust_counts;
    let (_all_processed, all_discovered, _) = all_counts;

    // All-files scan should discover at least as many files as Rust-only
    assert!(
        all_discovered >= rust_discovered,
        "All-files scan discovered {} files, but Rust-only scan discovered {} files. This suggests filtering is broken.",
        all_discovered, rust_discovered
    );

    // If there are non-Rust files in fixtures, all-files should discover more
    // (This is informational - fixtures may only contain Rust files)
    if all_discovered > rust_discovered {
        println!(
            "✅ File extension filtering working: {} total files, {} Rust files",
            all_discovered, rust_discovered
        );
    } else {
        println!("ℹ️  Only Rust files found in fixtures directory");
    }

    println!("✅ File extension accuracy test passed");
}
