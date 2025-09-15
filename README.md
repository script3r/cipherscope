## CipherScope

<div align="center">
  <img src="cipherscope.png" alt="CipherScope Logo" width="350" height="350">
</div>

Fast, low-false-positive static scanner that finds third-party cryptographic libraries and call sites across 11 programming languages: Go, Java, C, C++, Rust, Python, PHP, Swift, Objective-C, Kotlin, and Erlang.

**NEW**: Now generates **Minimal Viable Cryptographic Bill of Materials (MV-CBOM)** for Post-Quantum Cryptography (PQC) readiness assessment.

### Install & Run

```bash
cargo build --release
./target/release/cipherscope .
```

Generate MV-CBOM (Cryptographic Bill of Materials):

```bash
./target/release/cipherscope . --cbom
```

JSONL and SARIF:

```bash
./target/release/cipherscope . --json > findings.jsonl
./target/release/cipherscope . --sarif findings.sarif
```

Key flags:
- `--cbom`: generate MV-CBOM (Minimal Viable Cryptographic Bill of Materials)
- `--threads N`: set thread pool size
- `--max-file-size MB`: skip large files (default 2)
- `--patterns PATH`: specify patterns file (default: `patterns.toml`)
- `--progress`: show progress bar during scanning
- `--include-glob GLOB` / `--exclude-glob GLOB`
- `--deterministic`: stable output ordering
- `--print-config`: print loaded `patterns.toml`
- `--dry-run`: list files to be scanned

### Output

Pretty table to stdout (default), optional JSONL/SARIF, and **MV-CBOM** for PQC readiness assessment.

#### MV-CBOM (Minimal Viable Cryptographic Bill of Materials)

CipherScope can generate a comprehensive cryptographic inventory in JSON format that follows the MV-CBOM specification. This enables:

- **Post-Quantum Cryptography (PQC) Risk Assessment**: Identifies algorithms vulnerable to quantum attacks (NIST Quantum Security Level 0)
- **Crypto-Agility Planning**: Provides detailed algorithm parameters and usage patterns
- **Supply Chain Security**: Maps dependencies between components and cryptographic assets

The MV-CBOM includes:
- **Cryptographic Assets**: Algorithms, certificates, and related crypto material with NIST security levels
- **Dependency Relationships**: Distinguishes between "uses" (actively called) vs "implements" (available but unused)
- **Parameter Extraction**: Key sizes, curves, and other algorithm-specific parameters

Example MV-CBOM snippet:
```json
{
  "bomFormat": "MV-CBOM",
  "specVersion": "1.0",
  "cryptoAssets": [
    {
      "bom-ref": "uuid-1234",
      "assetType": "algorithm",
      "name": "RSA",
      "assetProperties": {
        "primitive": "signature",
        "parameterSet": {"keySize": 2048},
        "nistQuantumSecurityLevel": 0
      }
    }
  ],
  "dependencies": [
    {
      "ref": "main-component",
      "dependsOn": ["uuid-1234"],
      "dependencyType": "uses"
    }
  ]
}
```

Example table:

```text
Language | Library | Count | Example
---------|---------|-------|--------
Rust | RustCrypto | 2 | src/main.rs:12 aes_gcm::Aes256Gcm
```

JSONL example:

```json
{"language":"Rust","library":"RustCrypto","file":"src/main.rs","span":{"line":12,"column":5},"symbol":"aes_gcm::Aes256Gcm","snippet":"use aes_gcm::Aes256Gcm;","detector_id":"detector-rust"}
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

#### High-Performance Architecture

CipherScope uses a **producer-consumer model** inspired by ripgrep to achieve maximum throughput on large codebases:

**Producer (Parallel Directory Walker)**:
- Uses `ignore::WalkParallel` for parallel filesystem traversal
- Automatically respects `.gitignore` files and skips hidden directories
- Critical optimization: avoids descending into `node_modules`, `.git`, and other irrelevant directories
- Language detection happens early to filter files before expensive operations

**Consumers (Parallel File Processors)**:
- Uses `rayon` thread pools for parallel file processing
- Batched processing (1000 files per batch) for better cache locality
- Comment stripping and preprocessing shared across all detectors
- Lockless atomic counters for progress tracking

**Key Optimizations**:
- **Ultra-fast language detection**: Direct byte comparison, no string allocations
- **Syscall reduction**: 90% fewer `metadata()` calls through early filtering  
- **Aho-Corasick prefiltering**: Skip expensive regex matching when no keywords found
- **Batched channel communication**: Reduces overhead between producer/consumer threads
- **Optimal thread configuration**: Automatically uses `num_cpus` for directory traversal

#### Performance Benchmarks

**File Discovery Performance**:
- **5M file directory**: ~20-30 seconds (previously 90+ seconds)
- **Throughput**: 150,000-250,000 files/second discovery rate
- **Processing**: 4+ GiB/s content scanning throughput

**Scalability**:
- Linear scaling with CPU cores for file processing
- Efficient memory usage through batched processing
- Progress reporting accuracy: 100% (matches `find` command results)

### Architecture

#### Detector Architecture

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

#### MV-CBOM Architecture

The MV-CBOM generation is implemented in the `cbom-generator` crate with modular components:

- **cbom-generator**: Main CBOM generation and JSON serialization
- **certificate-parser**: X.509 certificate parsing and signature algorithm extraction  
- **algorithm-detector**: **Pattern-driven** algorithm detection using `patterns.toml` definitions
- **dependency-analyzer**: Intelligent "uses" vs "implements" relationship detection
- **project-parser**: Multi-language project metadata and dependency analysis (Cargo, Maven, go.mod, requirements.txt, Makefile, Bazel, BUCK, etc.)

**Key Innovation: Pattern-Driven Algorithm Detection**
- Algorithm definitions moved from hardcoded Rust to configurable `patterns.toml`
- Each library can define supported algorithms with NIST security levels
- Parameter extraction patterns (key sizes, curves) defined declaratively
- Extensible: new algorithms added by editing patterns, not code

The MV-CBOM pipeline:
1. **Static Analysis**: Scanner finds cryptographic usage patterns using `patterns.toml`
2. **Algorithm Detection**: **Pattern-driven** extraction of algorithms and parameters
3. **Certificate Parsing**: Discovers and analyzes X.509 certificates in the project
4. **Project Analysis**: Multi-language dependency parsing (Cargo, Maven, go.mod, Makefile, Bazel, BUCK, etc.)
5. **Dependency Analysis**: Correlates project dependencies with actual code usage
6. **CBOM Generation**: Produces standards-compliant JSON with NIST security levels

### Tests & Benchmarks

Run unit tests and integration tests (fixtures):

```bash
cargo test
```

#### Comprehensive Fixtures for MV-CBOM Testing

The `fixtures/` directory contains rich, realistic examples for testing MV-CBOM generation across multiple languages and build systems:

**Rust Fixtures:**
- **`rust/rsa-vulnerable`**: RSA 2048-bit usage (PQC vulnerable, "uses" relationship)
- **`rust/aes-gcm-safe`**: Quantum-safe algorithms (AES-256-GCM, ChaCha20Poly1305, SHA-3, BLAKE3)
- **`rust/implements-vs-uses`**: SHA2 "uses" vs P256 "implements" distinction
- **`rust/mixed-crypto`**: Complex multi-algorithm project (RSA, AES, SHA2, Ed25519, Ring)

**Java Fixtures:**
- **`java/maven-bouncycastle`**: Maven project with BouncyCastle RSA/ECDSA
- **`java/bazel-tink`**: Bazel project with Google Tink and BouncyCastle
- **`java/jca-standard`**: Standard JCA/JCE without external dependencies

**C/C++ Fixtures:**
- **`c/openssl-mixed`**: OpenSSL + libsodium with RSA, ChaCha20Poly1305, AES
- **`c/libsodium-modern`**: Modern libsodium with quantum-safe and vulnerable algorithms
- **`c/makefile-crypto`**: Basic OpenSSL usage with Makefile dependency detection
- **`cpp/botan-modern`**: Botan library with RSA, AES-GCM, SHA-3, BLAKE2b
- **`cpp/cryptopp-legacy`**: Crypto++ library with RSA, AES-GCM, SHA-256/512

**Go Fixtures:**
- **`go/stdlib-crypto`**: Standard library crypto (RSA, ECDSA, AES-GCM, SHA-256/512)
- **`go/x-crypto-extended`**: Extended crypto with golang.org/x/crypto dependencies

**Python Fixtures:**
- **`python/cryptography-mixed`**: PyCA Cryptography with RSA, AES, PBKDF2
- **`python/pycryptodome-legacy`**: PyCryptodome with RSA signatures and AES
- **`python/requirements-basic`**: Basic requirements.txt with Fernet and hashing

**Certificate Fixtures:**
- **`certificates/x509-rsa-ecdsa`**: X.509 certificates with RSA and ECDSA signatures

Run fixture tests:
```bash
# Test RSA vulnerability detection
./target/release/cipherscope fixtures/rust/rsa-vulnerable --cbom
cat fixtures/rust/rsa-vulnerable/mv-cbom.json | jq '.cryptoAssets[] | select(.assetProperties.nistQuantumSecurityLevel == 0)'

# Test multi-language support
./target/release/cipherscope fixtures/java/maven-bouncycastle --cbom
./target/release/cipherscope fixtures/go/stdlib-crypto --cbom
./target/release/cipherscope fixtures/python/cryptography-mixed --cbom

# Test certificate parsing
./target/release/cipherscope fixtures/certificates/x509-rsa-ecdsa --cbom
```

Benchmark scan throughput on test fixtures:

```bash
cargo bench
```

**Expected benchmark results** (on modern hardware):
- **Throughput**: ~4.2 GiB/s content processing
- **File discovery**: 150K-250K files/second  
- **Memory efficient**: Batched processing prevents memory spikes

**Real-world performance** (5M file Java codebase):
- **Discovery phase**: 20-30 seconds (down from 90+ seconds)
- **Processing phase**: Depends on file content and pattern complexity
- **Progress accuracy**: Exact match with `find` command results

To test progress reporting accuracy on your codebase:

```bash
# Count files that match your glob patterns
find /path/to/code -name "*.java" | wc -l

# Run cipherscope with same pattern - numbers should match
./target/release/cipherscope /path/to/code --include-glob "*.java" --progress
```

### Contributing

See `CONTRIBUTING.md` for guidelines on adding languages, libraries, and improving performance.

