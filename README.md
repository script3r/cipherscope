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
```bash
cargo install --path .
```

## Usage

Scan a directory for cryptographic assets:
```bash
cipherscope --roots /path/to/your/code --output results.jsonl
```

### Command-Line Arguments

- `-r, --roots <PATHS>`: One or more root directories to scan. Defaults to the current directory (`.`).
- `-e, --exclude <GLOBS>`: One or more glob patterns to exclude from the scan. For example, `vendor/**` or `*.min.js`.
- `-p, --patterns <PATH>`: Path to the `patterns.toml` file. Defaults to `patterns.toml` in the current directory.
- `-o, --output <PATH>`: Output file path for the JSONL results. Defaults to stdout (`-`).
- `--threads <NUM>`: The maximum number of parallel threads to use. Defaults to the number of available CPU cores.
- `-v, --progress`: Show progress bars during the scan.
- `--gitignore`: Respect `.gitignore` files (enabled by default).
- `--max-file-mb <MB>`: Skip files larger than this size (in megabytes) during discovery. Default: 1.

### Examples

**Scan the current directory and print results to the console:**
```bash
cipherscope
```

**Scan a specific project and save the output to a file:**
```bash
cipherscope --roots ~/projects/my-app -o my-app-crypto.jsonl
```

**Scan multiple directories at once:**
```bash
cipherscope --roots ~/projects/app1 --roots ~/projects/app2
```

**Scan a directory but exclude test and dependency folders:**
```bash
cipherscope --roots . --exclude '**/tests/**' --exclude '**/vendor/**'
```

**Skip oversized files (> 16 MB) during discovery:**
```bash
cipherscope --roots /path/to/repo --max-file-mb 16
```

The discovery progress will indicate how many files were skipped as oversized.

## Example Output

The output is a stream of JSONL objects, where each object represents a single finding.

**Library Finding:**
```json
{"assetType":"library","identifier":"OpenSSL","path":"/Users/user/dev/my-app/src/crypto.c","evidence":{"line":2,"column":1}}
```

**Algorithm Finding:**
```json
{"assetType":"algorithm","identifier":"AES-256-GCM","path":"/Users/user/dev/my-app/src/crypto.c","evidence":{"line":42,"column":18},"metadata":{"keysize":256,"primitive":"symmetric"}}
```

## Patterns

`cipherscope` relies on a `patterns.toml` file to define what to look for. This file contains definitions for:
