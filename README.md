## CipherScope

<div align="center">
  <img src="cipherscope.png" alt="CipherScope Logo" width="350" height="350">
</div>

**Cryptographic Bill of Materials (MV-CBOM) Generator** for Post-Quantum Cryptography (PQC) readiness assessment. 

Analyzes codebases across 11 programming languages (Go, Java, C, C++, Rust, Python, PHP, Swift, Objective-C, Kotlin, Erlang) and generates machine-readable JSON inventories of cryptographic assets with NIST quantum security levels.

### Install & Run

```bash
cargo build --release

# Generate MV-CBOM for current directory
./target/release/cipherscope .

# Generate MV-CBOMs recursively for all discovered projects
./target/release/cipherscope . --recursive
```

Key flags:
- `--recursive`: generate MV-CBOMs recursively for all discovered projects
- `--threads N`: set thread pool size  
- `--max-file-size MB`: skip large files (default 2)
- `--patterns PATH`: specify patterns file (default: `patterns.toml`)
- `--progress`: show progress bar during scanning
- `--print-config`: print loaded `patterns.toml`

### Output

**MV-CBOM JSON files** written to each project directory for comprehensive Post-Quantum Cryptography (PQC) readiness assessment.

#### MV-CBOM (Minimal Viable Cryptographic Bill of Materials)

CipherScope generates a comprehensive cryptographic inventory in JSON format that follows the MV-CBOM specification. This enables:

- **Post-Quantum Cryptography (PQC) Risk Assessment**: Identifies algorithms vulnerable to quantum attacks (NIST Quantum Security Level 0)
- **Crypto-Agility Planning**: Provides detailed algorithm parameters and usage patterns
- **Supply Chain Security**: Maps dependencies between components and cryptographic assets

The MV-CBOM includes:
- **Cryptographic Assets**: Algorithms, certificates, and related crypto material with NIST security levels
- **Dependency Relationships**: Distinguishes between "uses" (actively called) vs "implements" (available but unused)
- **Parameter Extraction**: Key sizes, curves, and other algorithm-specific parameters
- **Recursive Project Discovery**: Automatically discovers and analyzes nested projects (BUCK, Bazel, Maven modules, etc.)

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

### Configuration

Algorithm and library detection patterns are defined in `patterns.toml`. The schema supports:
- **Library Detection**: `include`/`import`/`namespace`/`apis` patterns per language
- **Algorithm Definitions**: Each library defines supported algorithms with NIST quantum security levels
- **Parameter Extraction**: Patterns for extracting key sizes, curves, and algorithm parameters

**Supported Languages**: C, C++, Java, Go, Rust, Python, PHP, Swift, Objective-C, Kotlin, Erlang

#### High-Performance Architecture

- **Parallel Processing**: Producer-consumer model with `rayon` thread pools
- **Smart Filtering**: Respects `.gitignore`, early language detection, Aho-Corasick prefiltering  
- **Scalable**: 4+ GiB/s throughput, linear scaling with CPU cores

### Architecture

**Modular MV-CBOM Generation Pipeline**:
1. **Project Discovery**: Recursive scanning for project files (BUILD, pom.xml, Cargo.toml, etc.)
2. **Static Analysis**: Pattern-driven cryptographic library detection
3. **Algorithm Detection**: Extract algorithms and parameters using `patterns.toml` definitions  
4. **Certificate Parsing**: X.509 certificate analysis with signature algorithms
5. **Dependency Analysis**: "Uses" vs "implements" relationship detection
6. **CBOM Generation**: Standards-compliant JSON with NIST quantum security levels

**Key Innovation**: Algorithm detection moved from hardcoded Rust to configurable `patterns.toml` - new algorithms added by editing patterns, not code.

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
./target/release/cipherscope fixtures/rust/rsa-vulnerable
jq '.cryptoAssets[] | select(.assetProperties.nistQuantumSecurityLevel == 0)' fixtures/rust/rsa-vulnerable/mv-cbom.json

# Test multi-language support
./target/release/cipherscope fixtures/java/maven-bouncycastle
./target/release/cipherscope fixtures/go/stdlib-crypto
./target/release/cipherscope fixtures/python/cryptography-mixed

# Test recursive project discovery
./target/release/cipherscope fixtures/buck-nested --recursive
./target/release/cipherscope fixtures/bazel-nested --recursive
```

Benchmark performance:

```bash
cargo test
cargo bench
```

### Contributing

See `CONTRIBUTING.md` for guidelines on adding languages, libraries, and improving performance.

