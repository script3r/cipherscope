# Code review, 2026-09-05

Reviewed baseline: `a659f1c` (main, including the previous modernization PR).
Scope: scanner/library implementation, CLI discovery and output, pattern loading,
test coverage, manifests/lockfile, CI/release workflows, and benchmark structure.
This is a targeted engineering review, not an exhaustive cryptographic catalog
validation or a performance study.

## Findings addressed by this series

| Priority | Finding and evidence | Change |
| --- | --- | --- |
| P1 | `--roots input.rs --output input.rs` returned success after reducing the source to zero bytes. Output was opened before validating exclusion globs. | [#14](https://github.com/script3r/cipherscope/pull/14): protect inputs, validate before output creation, stage output until success. |
| P1 | A nonexistent root printed a walk error but exited with status 0. Worker read/parse errors were also only logged. | [#14](https://github.com/script3r/cipherscope/pull/14): propagate incomplete scans through the exit status; preserve previous file output. |
| P1 | File-backed mmap had no protection against concurrent truncation or writes, violating the assumptions needed for safe access. The size limit was checked only during discovery. | [#14](https://github.com/script3r/cipherscope/pull/14): bounded reads into owned memory, including a read-time size check. |
| P2 | An OpenSSL include after a copyright comment produced no library finding. A node-anchored regex was reused against the whole file. | [#15](https://github.com/script3r/cipherscope/pull/15): conservative hints with authoritative AST matching. |
| P2 | A commented-out `EVP_aes_256_gcm()` generated an AES-GCM finding; API-only library anchors and comments inside call nodes could also match. | [#15](https://github.com/script3r/cipherscope/pull/15): mask AST comments while preserving evidence offsets. |
| P2 | `languages = ["Pythno"]` silently disabled the rule; unknown fields and unsupported schema versions were ignored. | [#16](https://github.com/script3r/cipherscope/pull/16): strict schema validation and contextual regex diagnostics. |
| P2 | Directory scans dropped `source.PY` despite the resolver accepting it. TSX was routed to a grammar without JSX syntax. | [#17](https://github.com/script3r/cipherscope/pull/17): one extension resolver, dedicated TSX parsing, C-only fixture coverage. |
| P2 | The lockfile contained three dependencies covered by active RustSec advisories; CI did not audit them. | This PR: targeted patched versions and recurring dependency auditing. |
| P2 | CI tested only Linux, all features, and no features; the advertised MSRV and individual parsers were unchecked. Actions used mutable major tags and older runtimes. | This PR: platform/feature/MSRV coverage, current action versions pinned to commits, Dependabot, and matching pre-commit checks. |

The mmap concern is supported by the library's
[documented safety contract](https://docs.rs/memmap2/latest/memmap2/struct.MmapOptions.html#safety).
Owned reads remove that memory-safety hazard but do not provide an atomic snapshot
of a repository while other processes edit it.

## Dependency evidence

`cargo-audit 0.22.2` checked 136 locked dependencies against RustSec database commit
`5a0ebedfe8bdd2e295b171f4162f8c977bcad9a5` (updated September 2, 2026).

| Package | Baseline | Patched version | Advisory |
| --- | --- | --- | --- |
| crossbeam-epoch | 0.9.18 | 0.9.20 | [RUSTSEC-2026-0204](https://rustsec.org/advisories/RUSTSEC-2026-0204.html) |
| anyhow | 1.0.100 | 1.0.103 | [RUSTSEC-2026-0190](https://rustsec.org/advisories/RUSTSEC-2026-0190.html) |
| memmap2 | 0.9.9 | 0.9.11 | [RUSTSEC-2026-0186](https://rustsec.org/advisories/RUSTSEC-2026-0186.html) |

The first is classified as a vulnerability; the other two are informational
unsoundness advisories. Reachability of the affected dependency functions from the
scanner has not been established. Source inspection found no direct calls to the
affected `anyhow` or `memmap2` APIs. The patched lockfile passes `cargo audit --deny
warnings`. PR #14 has merged and removed memmap2 entirely. This PR retains that
removal and patches the remaining anyhow and crossbeam-epoch dependencies; the
combined lockfile contains 135 dependencies.

## Remaining issues and follow-up acceptance criteria

- **Constant resolution ignores scope (P2).** `collect_constants` builds one map
  for the entire file, and textual substitution does not distinguish identifiers
  from string contents. A Python function-local `KEY_SIZE = 256` can overwrite a
  module-level `KEY_SIZE = 128` in the map, reporting 256 for the module-level
  call. Replace this with scope-aware resolution, or decline ambiguous
  substitutions; test shadowing, reassignment, string literals, and forward use.
- **Exclusions are relative to the process directory (P2).**
  `OverrideBuilder::new(".")` does not anchor `vendor/**` to an external scan root.
  Define per-root exclusion semantics and test absolute roots, multiple roots,
  anchored globs, and nested dependency directories.
- **Repeated/overlapping roots repeat findings (P2).** The walker receives every
  root and there is no cross-file identity deduplication. Choose and document
  whether identity means canonical path or inode, accounting for explicitly
  requested ignored paths and the memory cost of tracking every file.
- **Evidence and deduplication are coarse (P2).** API-only library findings always
  use line 1, column 1. Algorithm hits are collapsed per line, generic algorithms
  can be suppressed by separate calls on that line, and one parameterized hit can
  suppress all parameterless hits for the algorithm in the file. Define callsite
  identity and metadata precedence before changing this policy and its fixtures.
- **The catalog needs a separate semantic review (P2).** It contains duplicate
  algorithm definitions and three parameter patterns without capture group 1:
  RustCrypto/ChaCha20Poly1305 `keySize`, PyCA/Fernet `algorithm`, and
  CommonCrypto (Objective-C)/AES `mode`. They cannot extract values under the
  current implementation. `nistQuantumSecurityLevel` is parsed but never emitted.
  Establish intended semantics against official library documentation before
  changing these definitions. Do not automatically expose unvalidated security
  classifications in output.
- **Coverage and performance limits (P3).** Ordinary strings/docstrings can still
  trigger regex fallback. Imports/aliases and data flow are not fully resolved.
  Kotlin and Erlang catalog entries have no parsers. Component benchmarks assume
  certain parser features and are not reliable as a feature-isolation test suite.
  Benchmark owned reads and comment masking on representative repositories before
  making new throughput claims.

No `patterns.toml` or fixture files were modified in this series. Existing fixture
agreement establishes compatibility; the added negative and boundary tests cover
defects that the original positive-heavy fixture suite did not exercise.

## Validation and rollout

Each code PR was checked with formatting and warnings-denied Clippy before commit.
All-feature and minimal-feature tests pass; the source-language PR also passes
C-only and TypeScript-only suites. Rust 1.88 all-target/all-feature compilation,
`actionlint`, and the patched dependency audit pass locally. Expanded CI exercises
the other platforms and parser combinations on GitHub.

PRs #14–#17 have merged into main. PR #14 changed output behavior:
it requires a writable destination directory, rejects source/symlink
destinations, and preserves previous file output when scanning fails. #17 adds a
public `Language::Tsx` variant. #16 rejects configuration previously ignored.
The workflow changes do not publish a release during this review; the live release
upload and crates.io publication path remains unexecuted.

PR #18 includes the latest main and resolves the dependency conflicts by retaining
the removal of memmap2 and the patched anyhow/crossbeam-epoch versions.
