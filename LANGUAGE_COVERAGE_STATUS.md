# Language Coverage Status

## Currently Supported Languages (AST-based detection)

✅ **C** - 9 fixture files, OpenSSL library detection
✅ **C++** - 12 fixture files, OpenSSL/Botan/CryptoPP library detection  
✅ **Rust** - 13 fixture files, Ring/RustCrypto library detection
✅ **Python** - 16 fixture files, Cryptography library detection
✅ **Java** - 13 fixture files, JCA/BouncyCastle library detection
✅ **Go** - 12 fixture files, std-crypto/x-crypto library detection

**Total**: 37 ground truth files generated for supported languages

## Languages with Fixtures but No AST Support Yet

⏳ **PHP** - 9 fixture files (OpenSSL/Sodium libraries)
⏳ **Swift** - 9 fixture files (CryptoKit/CommonCrypto libraries)  
⏳ **Kotlin** - 5 fixture files (JCA library)
⏳ **Objective-C** - 9 fixture files (CommonCrypto/OpenSSL libraries)
⏳ **Erlang** - 5 fixture files (OTP-crypto library)

**Total**: 37 fixture files without AST support

## Why Some Languages Aren't Supported Yet

The missing languages have inconsistent or incompatible tree-sitter parser APIs:

- **tree-sitter-php**: Uses different function naming convention
- **tree-sitter-swift**: Uses `LANGUAGE` constant instead of `language()` function
- **tree-sitter-kotlin**: Different API structure
- **Objective-C**: No stable tree-sitter parser available
- **Erlang**: No stable tree-sitter parser available

## Detection Quality by Language

### High Quality Detection
- **C/C++**: Detects include statements and function calls accurately
- **Python**: Detects import statements and algorithm usage
- **Java**: Detects import statements for crypto APIs
- **Go**: Detects import statements for crypto packages

### Needs Refinement
- **Rust**: Currently generates many false positives (51 findings for a simple file)
  - AST patterns are too broad and match every identifier
  - Need more specific patterns for crypto-specific usage

## How to Add New Language Support

1. **Add tree-sitter parser dependency** to Cargo.toml
2. **Add parser initialization** in `AstDetector::new()`
3. **Add language matching** in `find_matches()` method
4. **Define AST patterns** for the language in `default_patterns()` or patterns.toml
5. **Add detector** in CLI main.rs
6. **Test and validate** with existing fixtures

## Future Improvements

1. **Refine Rust patterns** to reduce false positives
2. **Add support for missing languages** with stable tree-sitter parsers
3. **Enhance algorithm detection** with parameter extraction
4. **Add more library patterns** for comprehensive coverage
5. **Consider fallback regex detection** for languages without AST support

## Current Tool Usage

The tool currently works well for the 6 supported languages:

```bash
./target/release/cipherscope fixtures/python/cryptography/ --patterns patterns.toml
./target/release/cipherscope fixtures/c/openssl/ --patterns patterns.toml  
./target/release/cipherscope fixtures/java/jca/ --patterns patterns.toml
```

For unsupported languages, the tool will simply skip the files (no errors, just no output).