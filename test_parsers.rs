#!/usr/bin/env cargo +nightly -Zscript

//! Test script to check tree-sitter parser APIs

use tree_sitter::Parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing tree-sitter parser APIs...");
    
    // Test PHP parser
    println!("PHP parser:");
    match create_php_parser() {
        Ok(_) => println!("  ✅ PHP parser works"),
        Err(e) => println!("  ❌ PHP parser failed: {}", e),
    }
    
    Ok(())
}

fn create_php_parser() -> Result<Parser, Box<dyn std::error::Error>> {
    let mut parser = Parser::new();
    
    // Try different API patterns for PHP
    let language = tree_sitter_php::language();
    parser.set_language(&language)?;
    Ok(parser)
}