# CipherScope

<div align="center">
  <img src="cipherscope.png" alt="CipherScope Logo" width="350" height="350">
</div>

Fast AST-based cryptographic library and algorithm detection tool. Uses Abstract Syntax Tree parsing to precisely identify cryptographic usage in source code and outputs findings in JSONL format.

## Quick Start

```bash
cargo build --release
./target/release/cipherscope --progress /path/to/scan [... paths]
```

## What It Does

- **AST-based detection** - Uses tree-sitter parsers for precise source code analysis
- **Library detection** - Identifies crypto libraries via import/include/using statements
- **Algorithm detection** - Finds algorithm usage via method names, function calls, and type definitions
- **Multi-language support** - C, C++, Rust, Python, Java, Go
- **JSONL output** - Simple one-JSON-object-per-line format for easy processing
- **Fast parallel scanning** - Efficient processing of large codebases

## Example Output

```jsonl
{"language":"C","library":"OpenSSL","symbol":"<openssl/evp.h>","file":"src/main.c","line":1,"column":10,"snippet":"<openssl/evp.h>","detector":"ast-detector-c"}
{"language":"Python","library":"cryptography","symbol":"cryptography.hazmat.primitives.ciphers","file":"app.py","line":1,"column":6,"snippet":"cryptography.hazmat.primitives.ciphers","detector":"ast-detector-python"}
{"language":"Rust","library":"ring","symbol":"ring::aead","file":"main.rs","line":1,"column":5,"snippet":"ring::aead","detector":"ast-detector-rust"}
```

## Options

### Core Options
- `--progress` - Show progress bar during scanning
- `--deterministic` - Reproducible output for testing
- `--output FILE` - Output file for JSONL results (default: stdout)

### Filtering & Performance
- `--threads N` - Number of processing threads
- `--max-file-size MB` - Maximum file size to scan (default: 2MB)
- `--include-glob GLOB` - Include files matching glob pattern(s)
- `--exclude-glob GLOB` - Exclude files matching glob pattern(s)

## Languages Supported

C, C++, Go, Java, Python, Rust (AST-based detection)

## How It Works (High-Level)

1. **File Discovery** - Walks files respecting .gitignore and language detection
2. **AST Parsing** - Uses tree-sitter parsers to build Abstract Syntax Trees for each supported language
3. **Pattern Matching** - Executes tree-sitter queries to find:
   - **Library imports** - `#include`, `import`, `use` statements for crypto libraries
   - **Algorithm usage** - Function calls, method invocations, type references
4. **Result Emission** - Outputs findings as JSONL with precise location information

The AST-based approach provides more accurate detection than regex patterns by understanding the actual structure of the code.

## Testing

```bash
cargo test
```

## License

MIT
