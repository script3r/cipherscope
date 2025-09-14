## CipherScope

<div align="center">
  <img src="cipherscope.png" alt="CipherScope Logo" width="350" height="350">
</div>

Fast, low-false-positive static scanner that finds third-party cryptographic libraries and call sites across 11 programming languages: Go, Java, C, C++, Rust, Python, PHP, Swift, Objective-C, Kotlin, and Erlang.

### Install & Run

```bash
cargo build --release
./target/release/cipherscope .
```

JSONL and SARIF:

```bash
./target/release/cipherscope . --json > findings.jsonl
./target/release/cipherscope . --sarif findings.sarif
```

Key flags:
- `--min-confidence 0.9`: filter low-confidence hits
- `--threads N`: set thread pool size
- `--max-file-size MB`: skip large files (default 2)
- `--patterns PATH`: specify patterns file (default: `patterns.toml`)
- `--progress`: show progress bar during scanning
- `--include-glob GLOB` / `--exclude-glob GLOB`
- `--allow LIB` / `--deny LIB`
- `--deterministic`: stable output ordering
- `--fail-on-find`: exit 2 if findings exist
- `--print-config`: print loaded `patterns.toml`
- `--dry-run`: list files to be scanned

### Output

Pretty table to stdout (default) and optional JSONL/SARIF.

Example table:

```text
Language | Library | Count | Example
---------|---------|-------|--------
Rust | RustCrypto | 2 | src/main.rs:12 aes_gcm::Aes256Gcm
```

JSONL example:

```json
{"language":"Rust","library":"RustCrypto","file":"src/main.rs","span":{"line":12,"column":5},"symbol":"aes_gcm::Aes256Gcm","snippet":"use aes_gcm::Aes256Gcm;","confidence":0.99,"detector_id":"detector-rust"}
```

SARIF snippet:

```json
{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cipherscope"}},"results":[{"ruleId":"detector-rust","message":{"text":"RustCrypto in Rust"}}]}]}
```

### Configuration & Patterns

Patterns are loaded from `patterns.toml` (and optional `patterns.local.toml`, if you add it). The schema supports per-language `include`/`import`/`namespace`/`apis` anchored regexes. The engine strips comments and avoids string literals to reduce false positives.

#### Supported Languages & File Extensions

The scanner automatically detects and processes files with these extensions:

- **C/C++**: `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.c++`, `.hpp`, `.hxx`, `.h++`, `.hh`
- **Java**: `.java`
- **Go**: `.go`
- **Rust**: `.rs`
- **Python**: `.py`, `.pyw`, `.pyi`
- **PHP**: `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.phps`
- **Swift**: `.swift`
- **Objective-C**: `.m`, `.mm`, `.M`
- **Kotlin**: `.kt`, `.kts`
- **Erlang**: `.erl`, `.hrl`, `.beam`

#### Performance Optimizations

- **Default Glob Filtering**: Only processes source files, skipping documentation, images, and binaries
- **Pattern Caching**: Compiled patterns are cached per language for faster lookups
- **Aho-Corasick Prefiltering**: Fast substring matching before expensive regex operations
- **Parallel Processing**: Multi-threaded file scanning using Rayon

### Detector Architecture

The scanner uses a modular detector architecture with dedicated crates for each language:

- **detector-c**: C language support
- **detector-cpp**: C++ language support  
- **detector-go**: Go language support
- **detector-java**: Java language support
- **detector-rust**: Rust language support
- **detector-python**: Python language support
- **detector-php**: PHP language support
- **detector-swift**: Swift language support
- **detector-objc**: Objective-C language support
- **detector-kotlin**: Kotlin language support
- **detector-erlang**: Erlang language support

Each detector implements the `Detector` trait and can be extended independently. To add support for a new language, create a new detector crate under `crates/` or extend the `patterns.toml` to cover additional libraries. See `crates/scanner-core/src/lib.rs` for the trait definition and pattern-driven detector implementation.

### Tests & Benchmarks

Run unit tests and integration tests (fixtures):

```bash
cargo test
```

Benchmark scan throughput:

```bash
cargo bench
```

### Contributing

See `CONTRIBUTING.md` for guidelines on adding languages, libraries, and improving performance.

