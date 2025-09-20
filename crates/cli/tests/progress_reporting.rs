//! Progress reporting tests to ensure accurate counting and prevent regression

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use scanner_core::{Config, PatternRegistry, Scanner, AstBasedDetector, Language, Detector};

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
    // Create AST-based detectors
    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(AstBasedDetector::new(
            "ast-detector-c",
            &[Language::C],
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-java",
            &[Language::Java],
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-python",
            &[Language::Python],
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-rust",
            &[Language::Rust],
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-go",
            &[Language::Go],
        ).unwrap()),
    ];

    // Set up progress capture
    let progress_capture = ProgressCapture::new();
    let progress_callback = progress_capture.create_callback();

    let config = Config {
        progress_callback: Some(progress_callback),
        ..Default::default()
    };

    let registry = PatternRegistry::empty();
    let scanner = Scanner::new(&registry, detectors, config);

    // Scan the fixtures directory
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixtures_dir = workspace.join("fixtures");

    let _findings = scanner.run(&[fixtures_dir]).unwrap();

    // Verify progress reporting
    let final_counts = progress_capture.get_final_counts();
    assert!(final_counts.is_some(), "Progress callback should be called");

    let (processed, discovered, findings) = final_counts.unwrap();
    assert!(processed > 0, "Should have processed some files");
    assert!(discovered > 0, "Should have discovered some files");
    // Note: findings might vary based on AST detection

    println!(
        "Progress final counts: processed={}, discovered={}, findings={}",
        processed, discovered, findings
    );
}

#[test]
fn test_progress_monotonic_increase() {
    // Test that progress counts only increase (never decrease)
    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(AstBasedDetector::new(
            "ast-detector-rust",
            &[Language::Rust],
        ).unwrap()),
    ];

    let progress_capture = ProgressCapture::new();
    let progress_callback = progress_capture.create_callback();

    let config = Config {
        progress_callback: Some(progress_callback),
        include_globs: vec!["**/*.rs".to_string()],
        ..Default::default()
    };

    let registry = PatternRegistry::empty();
    let scanner = Scanner::new(&registry, detectors, config);

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixtures_dir = workspace.join("fixtures");

    let _findings = scanner.run(&[fixtures_dir]).unwrap();

    // Verify monotonic increase
    let all_updates = progress_capture.get_all_updates();
    assert!(!all_updates.is_empty(), "Should have received progress updates");

    let mut last_processed = 0;
    let mut last_discovered = 0;
    let mut last_findings = 0;

    for (processed, discovered, findings) in &all_updates {
        assert!(
            *processed >= last_processed,
            "Processed count should never decrease: {} -> {}",
            last_processed,
            processed
        );
        assert!(
            *discovered >= last_discovered,
            "Discovered count should never decrease: {} -> {}",
            last_discovered,
            discovered
        );
        assert!(
            *findings >= last_findings,
            "Findings count should never decrease: {} -> {}",
            last_findings,
            findings
        );

        last_processed = *processed;
        last_discovered = *discovered;
        last_findings = *findings;
    }

    println!("✅ Monotonic increase test passed with {} updates", all_updates.len());
}

#[test]
fn test_progress_file_extension_accuracy() {
    // Test that file extension filtering works correctly with progress reporting
    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(AstBasedDetector::new(
            "ast-detector-java",
            &[Language::Java],
        ).unwrap()),
    ];

    let progress_capture = ProgressCapture::new();
    let progress_callback = progress_capture.create_callback();

    let config = Config {
        progress_callback: Some(progress_callback),
        include_globs: vec!["**/*.java".to_string()], // Only Java files
        ..Default::default()
    };

    let registry = PatternRegistry::empty();
    let scanner = Scanner::new(&registry, detectors, config);

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixtures_dir = workspace.join("fixtures");

    let _findings = scanner.run(&[fixtures_dir]).unwrap();

    let final_counts = progress_capture.get_final_counts();
    assert!(final_counts.is_some(), "Should have progress updates");

    let (processed, discovered, _findings) = final_counts.unwrap();
    
    // We should have discovered and processed only Java files
    assert_eq!(
        processed, discovered,
        "All discovered files should be processed"
    );

    println!(
        "Java-only scan: processed={}, discovered={}",
        processed, discovered
    );
}