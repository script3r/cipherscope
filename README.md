# CipherScope

<div align="center">
  <img src="cipherscope.png" alt="CipherScope Logo" width="350" height="350">
</div>

Fast cryptographic inventory generator that creates Minimal Viable Cryptographic Bill of Materials (MV-CBOM) documents. Scans codebases to identify cryptographic algorithms, certificates, and assess post-quantum cryptography readiness.

## Quick Start

```bash
cargo build --release
./target/release/cipherscope --patterns patterns.toml --progress /path/to/scan [... paths]
```

## What It Does

- **Detects** cryptographic usage across 11 languages
- **Identifies** many cryptographic algorithms (AES, SHA, RSA, ECDSA, ChaCha20, etc.)
- **Outputs** JSON inventory with NIST quantum security levels
- **Runs fast** - GiB/s throughput with parallel scanning

## Example Output

```json
{
  "bomFormat": "MV-CBOM",
  "specVersion": "1.0",
  "cryptoAssets": [{
    "name": "RSA",
    "assetProperties": {
      "primitive": "signature",
      "parameterSet": {"keySize": 2048},
      "nistQuantumSecurityLevel": 0
    }
  }]
}
```

## Options

### Core Options
- `--patterns PATH` - Custom patterns file (default: `patterns.toml`)
- `--progress` - Show progress bar during scanning
- `--deterministic` - Reproducible output for testing/ground-truth generation
- `--output FILE` - Output file for single-project CBOM (default: stdout)
- `--recursive` - Generate MV-CBOMs for all discovered projects
- `--output-dir DIR` - Output directory for recursive CBOMs

### Filtering & Performance
- `--threads N` - Number of processing threads
- `--max-file-size MB` - Maximum file size to scan (default: 2MB)
- `--include-glob GLOB` - Include files matching glob pattern(s)
- `--exclude-glob GLOB` - Exclude files matching glob pattern(s)

### Certificate Scanning
- `--skip-certificates` - Skip certificate scanning during CBOM generation

### Configuration
- `--print-config` - Print merged patterns/config and exit

## Languages Supported

C, C++, Go, Java, Kotlin, Python, Rust, Swift, Objective-C, PHP, Erlang

## Configuration

Edit `patterns.toml` to add new libraries or algorithms. No code changes needed.

## How It Works (High-Level)

1. Workspace discovery and prefilter
   - Walks files respecting .gitignore
   - Cheap Aho-Corasick prefilter using language-specific substrings derived from patterns
2. Language detection and comment stripping
   - Detects language by extension; strips comments once for fast regex matching
3. Library identification (anchors)
   - Per-language detector loads compiled patterns for that language (from `patterns.toml`)
   - Looks for include/import/namespace/API anchors to confirm a library is present in a file
4. Algorithm matching
   - For each identified library, matches algorithm `symbol_patterns` (regex) against the file
   - Extracts parameters via `parameter_patterns` (e.g., key size, curve) with defaults when absent
   - Emits findings with file, line/column, library, algorithm, primitive, and NIST quantum level
5. Deep static analysis (fallback/enrichment)
   - For small scans, analyzes files directly with the registry to find additional algorithms even if no library finding was produced
6. CBOM generation
   - Findings are deduplicated and merged
   - Final MV-CBOM JSON is printed or written per CLI options

All behavior is driven by `patterns.toml` — adding new libraries/algorithms is a data-only change.

## Testing

```bash
cargo test
```

## License

MIT
