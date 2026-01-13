# Benchmarking Cipherscope

This document explains how to run and interpret the benchmark suite.

## Quick Start

```bash
# Run all benchmarks (fast mode, ~5-8 minutes)
cargo bench

# Run extended benchmarks (~30 minutes)
CIPHERSCOPE_BENCH_EXTENDED=1 cargo bench

# Run a specific benchmark
cargo bench --bench component_bench
cargo bench --bench scale_bench
```

## Benchmark Modes

### Normal Mode (Default)
Runs essential benchmarks with minimal variants. Completes in **~5-8 minutes**.

### Extended Mode
Set `CIPHERSCOPE_BENCH_EXTENDED=1` to enable:
- More file size variants (1KB-1MB)
- More file count variants (100-10K)
- More thread counts (1,2,4,8,16,32)
- Memory profiling benchmarks
- Large fixture benchmarks (5K+ files)

## Benchmark Summary

| Benchmark | Normal Mode | Extended Mode |
|-----------|-------------|---------------|
| `scan_bench` | 4 variants (~1 min) | Same |
| `component_bench` | 8 variants (~1.5 min) | 15 variants (~3 min) |
| `file_size_bench` | 3 sizes (~1 min) | 5 sizes (~2 min) |
| `scale_bench` | 3 file counts (~1.5 min) | 6 counts + density (~5 min) |
| `thread_scaling_bench` | 3 thread counts (~1 min) | 7 thread counts (~3 min) |
| `memory_bench` | Skipped | 3 variants (~3 min) |
| `large_fixture_bench` | Skipped | 5K files + nested (~5 min) |

## Benchmark Details

### scan_bench
Basic end-to-end scan benchmark using the existing fixtures.
```bash
cargo bench --bench scan_bench
```

### component_bench
Isolates individual scanner components:
- `parsing` - Tree-sitter AST parsing
- `anchor_hint` - Fast regex pre-filter
- `library_anchors` - Library detection
- `algorithm_detection` - Pattern matching
- `full_pipeline` - Complete scan pipeline
- `language_detection` - File extension mapping
- `pattern_loading` - PatternSet initialization

```bash
cargo bench --bench component_bench
```

### file_size_bench
Tests performance with different file sizes (1KB, 10KB, 100KB, etc.).
```bash
cargo bench --bench file_size_bench
```

### scale_bench
Tests performance with different file counts (100, 500, 1000, etc.).
```bash
cargo bench --bench scale_bench
```

### thread_scaling_bench
Measures parallel scaling efficiency.
```bash
cargo bench --bench thread_scaling_bench
```

### memory_bench (Extended Only)
Profiles memory usage during scans.
```bash
CIPHERSCOPE_BENCH_EXTENDED=1 cargo bench --bench memory_bench
```

### large_fixture_bench (Extended Only)
Tests with large synthetic fixtures (5K+ files).
```bash
CIPHERSCOPE_BENCH_EXTENDED=1 cargo bench --bench large_fixture_bench
```

## Interpreting Results

Criterion reports time as a range:
```
parsing/lang/python     time:   [1.98 ms 2.00 ms 2.01 ms]
                        thrpt:  [4.76 MiB/s 4.79 MiB/s 4.83 MiB/s]
```

- First line: timing (low / median / high)
- Second line: throughput (if configured)

### Throughput Metrics
- `Elements/s`: Files scanned per second
- `MiB/s`: Data processed per second

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CIPHERSCOPE_BENCH_EXTENDED` | Enable extended benchmarks |
| `CIPHERSCOPE_BENCH_FIXTURE` | Custom fixture path for scan_large_bench |
| `CIPHERSCOPE_BENCH_THREADS` | Custom thread counts (comma-separated) |

## Tips

1. Close other applications to reduce noise
2. Run multiple times to verify consistency
3. Results are saved to `target/criterion/`
4. HTML reports: `target/criterion/<name>/report/index.html`

## Comparing Baselines

```bash
# Save baseline
cargo bench -- --save-baseline before

# Make changes, then compare
cargo bench -- --baseline before
```
