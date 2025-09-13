## Contributing to cryptofind

Thank you for improving cryptofind! This project aims for speed, precision, and extensibility.

### Adding a New Library via patterns

1. Edit `patterns.toml` and add a new `[[library]]` entry.
2. Use anchored regexes for `include`/`import`/`namespace`/`apis`.
3. Prefer import/include anchors; use API patterns only as secondary evidence.
4. Run `cargo test` to validate regex and stripper behavior.

### Adding a New Language or Custom Detector

1. Create a new crate under `crates/detector-<lang>/`.
2. Implement the `Detector` trait from `scanner-core`.
3. Provide `prefilter()` substrings and extensions for fast filtering.
4. Use comment stripping utilities to avoid matches in comments/strings.

### Performance Guidelines

- Stream files and avoid unnecessary allocations.
- Use `rayon` for parallelism; keep per-file work independent.
- Prefer `aho-corasick` for prefilter substring matching.
- Short-circuit after sufficient evidence unless `--exhaustive` (future work).

### Testing

- Add unit tests for any new stripper rules.
- Provide fixtures under `fixtures/<lang>/positive` and `fixtures/<lang>/negative`.
- Add integration tests in `tests/` to cover the new patterns.

