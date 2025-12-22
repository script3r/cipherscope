# cipherscope

<div align="center">
  <img src="cipherscope.png" alt="CipherScope Logo" width="350" height="350">
</div>

[![CI](https://github.com/script3r/cipherscope/actions/workflows/ci.yml/badge.svg)](https://github.com/script3r/cipherscope/actions/workflows/ci.yml)

`cipherscope` is a high-performance, command-line tool for scanning source code to detect the usage of cryptographic libraries and algorithms. It uses language-aware static analysis powered by [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) for high precision.

## Key Features

- **High Performance**: Parallelized scanning of large codebases.
- **Language-Aware**: Uses Tree-sitter parsers to reduce false positives by understanding code structure.
- **Extensible Patterns**: Easily add new libraries and algorithms via a simple TOML configuration.
- **Broad Language Support**: Currently supports C, C++, Java, Python, Go, Swift, PHP, Objective-C, and Rust.
- **Developer Friendly**: JSONL output for easy integration with CI/CD pipelines and security tools.
- **Cross-Platform**: Native binaries for macOS, Linux, and Windows.

## How It Works

`cipherscope` operates in two main phases:

1.  **Discovery**: It walks the specified root directories in parallel, identifying source files based on their extensions. It respects `.gitignore` rules and can be configured to skip files that exceed a certain size to maintain speed.

2.  **Scanning**: Discovered files are processed in a thread pool:
    a.  **Parsing**: Each file is parsed into an Abstract Syntax Tree (AST) using the relevant Tree-sitter grammar.
    b.  **Anchoring**: The scanner looks for "library anchors" (e.g., `import` or `#include` statements) that match known cryptographic libraries defined in `patterns.toml`.
    c.  **Algorithm Detection**: If an anchor is found, the scanner performs a deeper search within that file for specific algorithm usage patterns, such as function calls and constants.

All results are streamed as JSONL to the output, allowing for real-time monitoring and processing.

## Installation

Ensure you have the Rust toolchain installed. You can install it from [rustup.rs](https://rustup.rs/).

Then, install `cipherscope` using `cargo`:
```bash
cargo install --path .
```

## Usage

```bash
cipherscope [OPTIONS]
```

### Options

- `-r, --roots <PATHS>`: One or more root directories to scan (default: `.`).
- `-e, --exclude <GLOBS>`: Glob patterns to exclude from the scan (e.g., `vendor/**`).
- `-p, --patterns <PATH>`: Path to the `patterns.toml` file (default: `patterns.toml`).
- `-o, --output <PATH>`: Output file path for JSONL results (default: stdout).
- `--threads <NUM>`: Maximum number of parallel threads to use.
- `-v, --progress`: Enable progress bars for discovery and scanning.
- `--gitignore`: Respect `.gitignore` files (default: true).
- `--max-file-mb <MB>`: Skip files larger than this size in megabytes (default: 1).

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
- **Libraries**: Anchors used to detect specific crypto libraries, like import statements.
- **Algorithms**: Symbols and function calls associated with specific algorithms (e.g., "AES-GCM") within a library.

You can customize this file to add support for new libraries or improve detection for existing ones.

## Development

### Building from Source
1. Clone the repository.
2. Build the project using Cargo:
   ```bash
   cargo build --release
   ```
   The binary will be located at `./target/release/cipherscope`.

### Running Tests
To run the integration test suite:
```bash
cargo test
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
