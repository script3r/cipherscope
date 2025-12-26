# Benchmarking Cipherscope

This document explains how to read the micro-benchmark results and what they do (and do not) measure.

## What the micro-benchmark measures

The benchmark is a full end-to-end scan using the compiled `cipherscope` binary. Each iteration:
- Walks the roots and discovers files (respecting ignore rules).
- Runs a fast regex anchor hint to skip files with no matching library/API patterns.
- Parses files into ASTs.
- Finds library anchors and algorithm hits.
- Writes JSONL output to a temp file.

This is an integrated measurement of scanner performance, not a unit benchmark of a single stage.

## Datasets used

The current benchmark runs two small fixed datasets:
- `fixtures`: `fixtures/` only (26 files).
- `repo_mix`: `fixtures/` + `src/` + `tests/` (30 files).

These datasets are intentionally small and fast to run. They are useful for regression tracking but not
representative of large codebases.

## Threading variants

Each dataset is benchmarked with:
- `1` thread.
- `num_cpus::get()` threads (full CPU on the current machine).

This shows scaling behavior on the same workload.

## Interpreting numbers

Criterion reports a time range per benchmark, e.g.:
```
scan/fixtures/1   time: [209.72 ms 210.81 ms 211.61 ms]
```

This range represents the typical runtime distribution (low/median/high) across samples.
For quick intuition, you can estimate throughput:
- `files/sec ≈ file_count / median_time_seconds`

Example:
- 26 files / 0.210 s ≈ 124 files/sec.

## Methodology summary

The benchmark:
- Uses `cargo bench --bench scan_bench`.
- Warms up for ~3 seconds.
- Collects 10 samples over ~10 seconds per case.
- Shells out to the compiled binary and writes JSONL to a temp file.

This keeps the timing focused on real scanning work while avoiding stdout overhead.

## Large-scale benchmark

For a more realistic scan, the `scan_large_bench` benchmark targets a folder
containing multiple large repositories. It is opt-in and can be run with:
```
CIPHERSCOPE_BENCH_FIXTURE=/path/to/fixture cargo bench --bench scan_large_bench
```

If `CIPHERSCOPE_BENCH_FIXTURE` is not set, the benchmark defaults to
`../cipherscope-paper/fixture` relative to the `cipherscope` repo. The large
benchmark uses fewer samples and a longer measurement window to accommodate
large repos.

## Limitations and caveats

- Results are machine- and filesystem-dependent.
- Small datasets can exaggerate overhead and reduce signal.
- OS caching can make repeated scans faster than cold-cache runs.
- The output writing cost is included (to a temp file).

## When to extend the benchmark

For larger or more realistic measurements, consider:
- Adding a larger repo checkout as an additional dataset.
- Reporting total bytes scanned to compute MB/sec.
- Running explicit cold-cache tests.
- Adding a "no-output" mode for pure scanning cost.
