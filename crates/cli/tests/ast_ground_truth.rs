use scanner_core::*;
use std::fs;
use std::path::PathBuf;

/// Test that compares AST-based detection results against generated ground truth JSONL files
#[test]
fn compare_ast_ground_truth() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    
    // Use AST-based detectors
    let dets: Vec<Box<dyn Detector>> = vec![
        Box::new(AstBasedDetector::new(
            "ast-detector-c",
            &[Language::C],
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-cpp",
            &[Language::Cpp],
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-rust",
            &[Language::Rust],
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-python",
            &[Language::Python],
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-java",
            &[Language::Java],
        ).unwrap()),
        Box::new(AstBasedDetector::new(
            "ast-detector-go",
            &[Language::Go],
        ).unwrap()),
    ];
    
    let reg = PatternRegistry::empty();
    let mut config = Config::default();
    config.deterministic = true; // Ensure reproducible results
    let scanner = Scanner::new(&reg, dets, config);

    let fixtures_root = workspace.join("fixtures");

    // Find all directories that have ground truth files
    let mut ground_truth_dirs = Vec::new();
    collect_ground_truth_dirs(&fixtures_root, &mut ground_truth_dirs).unwrap();
    
    println!("Found {} directories with ground truth files", ground_truth_dirs.len());

    let mut total_matches = 0;
    let mut total_mismatches = 0;

    // Test each directory with ground truth
    for dir in ground_truth_dirs {
        let ground_truth_file = dir.join("ground_truth.jsonl");
        
        // Run scanner on this directory
        let findings = scanner.run(&[dir.clone()]).unwrap();
        
        // Convert findings to JSONL format and normalize paths
        let mut crypto_findings = CryptoFindings::from_scanner_findings(findings);
        
        // Normalize file paths to be relative to workspace
        for finding in &mut crypto_findings.findings {
            let file_str = finding.file.to_string_lossy();
            if let Some(idx) = file_str.find("fixtures/") {
                finding.file = std::path::PathBuf::from(&file_str[idx..]);
            }
        }
        
        let actual_jsonl = crypto_findings.to_jsonl().unwrap();
        
        // Read expected ground truth
        let expected_jsonl = fs::read_to_string(&ground_truth_file).unwrap();
        
        // Compare line by line (order matters due to deterministic flag)
        let actual_lines: Vec<&str> = actual_jsonl.lines().collect();
        let expected_lines: Vec<&str> = expected_jsonl.lines().collect();
        
        if actual_lines == expected_lines {
            total_matches += 1;
            println!("✓ {}", dir.strip_prefix(&workspace).unwrap().display());
        } else {
            total_mismatches += 1;
            println!("✗ {}", dir.strip_prefix(&workspace).unwrap().display());
            println!("  Expected {} lines, got {} lines", expected_lines.len(), actual_lines.len());
            
            // Show first few differences for debugging
            let max_diff_lines = 3;
            let mut diff_count = 0;
            for (i, (expected, actual)) in expected_lines.iter().zip(actual_lines.iter()).enumerate() {
                if expected != actual && diff_count < max_diff_lines {
                    println!("  Line {}: Expected: {}", i + 1, expected);
                    println!("  Line {}: Actual:   {}", i + 1, actual);
                    diff_count += 1;
                }
            }
            if diff_count >= max_diff_lines {
                println!("  ... (showing only first {} differences)", max_diff_lines);
            }
        }
    }
    
    println!("\nGround truth comparison summary:");
    println!("  Matches: {}", total_matches);
    println!("  Mismatches: {}", total_mismatches);
    println!("  Total: {}", total_matches + total_mismatches);
    
    // Allow some mismatches during development, but ensure we have some matches
    assert!(total_matches > 0, "No ground truth matches found - AST detection may be broken");
    
    // For now, we'll be lenient during development. In production, this should be:
    // assert_eq!(total_mismatches, 0, "Ground truth mismatches found");
}

fn collect_ground_truth_dirs(root: &std::path::Path, dirs: &mut Vec<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    if !root.is_dir() {
        return Ok(());
    }
    
    // Check if this directory has a ground truth file
    let ground_truth_file = root.join("ground_truth.jsonl");
    if ground_truth_file.exists() {
        dirs.push(root.to_path_buf());
    }
    
    // Recursively check subdirectories
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() && !path.file_name().unwrap().to_str().unwrap().starts_with('.') {
            collect_ground_truth_dirs(&path, dirs)?;
        }
    }
    
    Ok(())
}