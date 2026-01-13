//! Large-scale fixture benchmarks.
//!
//! These benchmarks test performance with large synthetic fixtures.
//! Requires extended mode due to long runtime.
//!
//! Run with: CIPHERSCOPE_BENCH_EXTENDED=1 cargo bench --bench large_fixture_bench
//! (Skipped in normal mode to keep benchmarks fast)

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::{NamedTempFile, TempDir};

mod fixture_generator;
use fixture_generator::{CodeTemplates, FixtureConfig, cleanup_fixture, generate_fixture};

fn is_extended() -> bool {
    std::env::var("CIPHERSCOPE_BENCH_EXTENDED").is_ok()
}

fn run_scan(roots: &[PathBuf], threads: usize, patterns_path: &Path) {
    let output = NamedTempFile::new().expect("create temp output file");
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cipherscope"));
    cmd.arg("--output")
        .arg(output.path())
        .arg("--threads")
        .arg(threads.to_string())
        .arg("--patterns")
        .arg(patterns_path);
    for root in roots {
        cmd.arg("--roots").arg(root);
    }
    let status = cmd.status().expect("run cipherscope");
    assert!(status.success(), "cipherscope exited with {status}");
}

/// Benchmark with a large fixture (5K files)
fn bench_large_fixture(c: &mut Criterion) {
    if !is_extended() {
        eprintln!("Skipping large_fixture_bench (set CIPHERSCOPE_BENCH_EXTENDED=1 to enable)");
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let patterns_path = repo_root.join("patterns.toml");
    let temp_dir = TempDir::new().expect("create temp directory");

    let config = FixtureConfig {
        file_count: 5000,
        file_size: 4096,
        crypto_density: 30,
        languages: vec![
            "python".to_string(),
            "c".to_string(),
            "java".to_string(),
            "go".to_string(),
            "rust".to_string(),
        ],
    };

    eprintln!(
        "Generating large fixture with {} files...",
        config.file_count
    );
    let start = Instant::now();
    let fixture_path = generate_fixture(temp_dir.path(), &config).expect("generate fixture");
    eprintln!("  Generated in {:?}", start.elapsed());

    let roots = vec![fixture_path.clone()];
    let total_bytes = (config.file_count * config.file_size) as u64;

    let mut group = c.benchmark_group("large_fixture");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Bytes(total_bytes));

    let max_cpus = num_cpus::get();
    let thread_counts: Vec<usize> = vec![1, max_cpus]
        .into_iter()
        .filter(|&t| t > 0 && t <= max_cpus)
        .collect();

    for threads in thread_counts {
        group.bench_with_input(
            BenchmarkId::new("threads", threads),
            &threads,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        run_scan(&roots, threads, &patterns_path);
                        total += start.elapsed();
                    }
                    total
                });
            },
        );
    }

    group.finish();
    let _ = cleanup_fixture(&fixture_path);
}

/// Benchmark with nested directory structure
fn bench_nested_directories(c: &mut Criterion) {
    if !is_extended() {
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let patterns_path = repo_root.join("patterns.toml");
    let temp_dir = TempDir::new().expect("create temp directory");

    let base_path = temp_dir.path().join("nested_fixture");
    std::fs::create_dir_all(&base_path).expect("create base dir");

    eprintln!("Generating nested directory structure...");
    let start = Instant::now();

    // Create nested structure: 5 levels × 5 dirs × 3 files = 1875 files
    let mut total_files = 0;
    for l1 in 0..5 {
        for l2 in 0..5 {
            for l3 in 0..5 {
                let dir_path = base_path
                    .join(format!("module_{}", l1))
                    .join(format!("submodule_{}", l2))
                    .join(format!("component_{}", l3));

                std::fs::create_dir_all(&dir_path).expect("create nested dir");

                for f in 0..3 {
                    let file_path = dir_path.join(format!("file_{}.py", f));
                    let content = CodeTemplates::python_crypto(2048);
                    std::fs::write(&file_path, content).expect("write file");
                    total_files += 1;
                }
            }
        }
    }

    eprintln!("  Generated {} files in {:?}", total_files, start.elapsed());

    let roots = vec![base_path.clone()];

    let mut group = c.benchmark_group("nested_directories");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Elements(total_files as u64));

    let threads = num_cpus::get();
    group.bench_function("scan", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                run_scan(&roots, threads, &patterns_path);
                total += start.elapsed();
            }
            total
        });
    });

    group.finish();
    let _ = std::fs::remove_dir_all(&base_path);
}

criterion_group!(benches, bench_large_fixture, bench_nested_directories);
criterion_main!(benches);
