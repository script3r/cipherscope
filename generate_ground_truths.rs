#!/usr/bin/env cargo +nightly -Zscript

//! Ground truth generation script for AST-based CipherScope
//! 
//! This script generates new ground truth JSONL files for all fixture directories
//! using the new AST-based detection approach.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating ground truths for AST-based CipherScope...");
    
    let workspace = PathBuf::from(".");
    let fixtures_root = workspace.join("fixtures");
    
    // Build the tool first
    println!("Building cipherscope...");
    let build_output = Command::new("cargo")
        .args(&["build", "--release"])
        .current_dir(&workspace)
        .output()?;
    
    if !build_output.status.success() {
        eprintln!("Failed to build cipherscope:");
        eprintln!("{}", String::from_utf8_lossy(&build_output.stderr));
        return Err("Build failed".into());
    }
    
    let cipherscope_bin = workspace.join("target/release/cipherscope");
    
    // Find all directories that contain source files
    let mut fixture_dirs = Vec::new();
    collect_fixture_dirs(&fixtures_root, &mut fixture_dirs)?;
    
    println!("Found {} fixture directories", fixture_dirs.len());
    
    // Generate ground truth for each directory
    for dir in fixture_dirs {
        println!("Processing: {}", dir.display());
        
        let output_file = dir.join("ground_truth.jsonl");
        
        // Run cipherscope on this directory
        let scan_output = Command::new(&cipherscope_bin)
            .args(&["--deterministic", "--output", output_file.to_str().unwrap(), dir.to_str().unwrap()])
            .current_dir(&workspace)
            .output()?;
        
        if !scan_output.status.success() {
            eprintln!("Warning: Failed to scan {}: {}", 
                     dir.display(), 
                     String::from_utf8_lossy(&scan_output.stderr));
            continue;
        }
        
        // Check if any findings were generated
        if output_file.exists() {
            let content = fs::read_to_string(&output_file)?;
            if content.trim().is_empty() {
                // Remove empty files
                fs::remove_file(&output_file)?;
                println!("  No findings - removed empty file");
            } else {
                let line_count = content.lines().count();
                println!("  Generated {} findings", line_count);
            }
        } else {
            println!("  No findings");
        }
    }
    
    println!("Ground truth generation complete!");
    Ok(())
}

fn collect_fixture_dirs(root: &Path, dirs: &mut Vec<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    if !root.is_dir() {
        return Ok(());
    }
    
    let mut has_source_files = false;
    let mut subdirs = Vec::new();
    
    // Check if this directory has source files
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if matches!(ext, "c" | "h" | "cpp" | "hpp" | "rs" | "py" | "java" | "go" | "js" | "php" | "m" | "mm" | "swift" | "kt" | "erl") {
                    has_source_files = true;
                }
            }
        } else if path.is_dir() && !path.file_name().unwrap().to_str().unwrap().starts_with('.') {
            subdirs.push(path);
        }
    }
    
    if has_source_files {
        dirs.push(root.to_path_buf());
    }
    
    // Recursively process subdirectories
    for subdir in subdirs {
        collect_fixture_dirs(&subdir, dirs)?;
    }
    
    Ok(())
}