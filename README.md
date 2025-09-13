## cryptofind

Fast, low-false-positive static scanner that finds third-party cryptographic libraries and call sites across Go, Java, C, C++, Rust, Python, PHP, Swift, Objective-C, and Kotlin codebases.

### Install & Run

```bash
cargo build --release
./target/release/cryptofind .
```

JSONL and SARIF:

```bash
./target/release/cryptofind . --json > findings.jsonl
./target/release/cryptofind . --sarif findings.sarif
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
{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cryptofind"}},"results":[{"ruleId":"detector-rust","message":{"text":"RustCrypto in Rust"}}]}]}
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

#### Performance Optimizations

- **Default Glob Filtering**: Only processes source files, skipping documentation, images, and binaries
- **Pattern Caching**: Compiled patterns are cached per language for faster lookups
- **Aho-Corasick Prefiltering**: Fast substring matching before expensive regex operations
- **Parallel Processing**: Multi-threaded file scanning using Rayon

### Extending Detectors

Detectors are plugin-like. Add a new crate under `crates/` implementing the `Detector` trait, or extend the `patterns.toml` to cover additional libraries. See `crates/scanner-core/src/lib.rs` for the trait and pattern-driven detector.

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

