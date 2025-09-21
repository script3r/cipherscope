# cipherscope

<div align="center">
  <img src="cipherscope.png" alt="CipherScope Logo" width="350" height="350">
</div>

[![CI](https://github.com/script3r/cipherscope/actions/workflows/ci.yml/badge.svg)](https://github.com/script3r/cipherscope/actions/workflows/ci.yml)

`cipherscope` is a fast, command-line tool for scanning source code to detect the usage of cryptographic libraries and algorithms. It uses static analysis powered by Tree-sitter for high-precision, language-aware scanning.

## Features

- **High Performance**: Scans large codebases quickly by leveraging parallelism.
- **Language-Aware**: Uses Tree-sitter parsers to understand code structure, reducing false positives.
- **Extensible Patterns**: Define custom patterns in a simple TOML file to find new libraries and algorithms.
- **Multiple Language Support**: Scans C, C++, Java, Python, Go, Swift, Objective-C, and Rust.
- **Flexible Output**: Outputs findings as JSONL to stdout or a file for easy integration with other tools.
- **Cross-Platform**: Built in Rust, runs on macOS, Linux, and Windows.

## How It Works

`cipherscope` works in two main phases: file discovery and scanning.

1.  **Discovery**: The tool walks the specified directory tree in parallel to find files matching the extensions of supported programming languages. It respects `.gitignore` files and can skip oversized files to keep the discovery process fast.

2.  **Scanning**: Each discovered file is then processed, also in parallel:
    a.  **Parsing**: The file content is parsed into an Abstract Syntax Tree (AST) using the appropriate Tree-sitter grammar for its language.
    b.  **Library Anchoring**: It looks for "library anchors" in the AST, which are typically `import` or `include` statements that match patterns defined in `patterns.toml`. This quickly identifies which cryptographic libraries might be in use.
    c.  **Algorithm Detection**: If a library anchor is found, the scanner then searches for specific algorithm patterns associated with that library. These patterns target function calls, constants, and other symbols to identify cryptographic primitives.

All findings are streamed as JSONL to the output, allowing you to see results in real-time.

## Installation

Ensure you have the Rust toolchain installed. You can install it from [rustup.rs](https://rustup.rs/).

Then, install `cipherscope` using `cargo`:
```
