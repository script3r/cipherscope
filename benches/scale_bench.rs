//! Benchmark for directory scale variation.
//!
//! This benchmark measures scanner performance across different file counts.
//!
//! Run with: cargo bench --bench scale_bench
//! Extended mode: CIPHERSCOPE_BENCH_EXTENDED=1 cargo bench --bench scale_bench

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tempfile::{NamedTempFile, TempDir};

mod fixture_generator;
use fixture_generator::{FixtureConfig, cleanup_fixture, generate_fixture};

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

fn bench_directory_scale(c: &mut Criterion) {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let patterns_path = repo_root.join("patterns.toml");
    let temp_dir = TempDir::new().expect("create temp directory");

    // Quick mode: 3 counts, Extended mode: 6 counts
    let file_counts: Vec<usize> = if is_extended() {
        vec![100, 500, 1000, 2500, 5000, 10000]
    } else {
        vec![100, 500, 1000]
    };

    let mut group = c.benchmark_group("directory_scale");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    let threads = num_cpus::get();

    for count in file_counts {
        let config = FixtureConfig {
            file_count: count,
            file_size: 2048,
            crypto_density: 50,
            languages: vec!["python".to_string(), "c".to_string(), "java".to_string()],
        };

        eprintln!("Generating fixture with {} files...", count);
        let fixture_path = generate_fixture(temp_dir.path(), &config).expect("generate fixture");
        let roots = vec![fixture_path.clone()];

        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(BenchmarkId::new("files", count), &count, |b, _count| {
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

        let _ = cleanup_fixture(&fixture_path);
    }

    group.finish();
}

/// Benchmark with varying crypto density (extended mode only)
fn bench_crypto_density(c: &mut Criterion) {
    if !is_extended() {
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let patterns_path = repo_root.join("patterns.toml");
    let temp_dir = TempDir::new().expect("create temp directory");

    let densities: Vec<u8> = vec![0, 50, 100];

    let mut group = c.benchmark_group("crypto_density");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    let threads = num_cpus::get();

    for density in densities {
        let config = FixtureConfig {
            file_count: 200,
            file_size: 4096,
            crypto_density: density,
            languages: vec!["python".to_string(), "c".to_string()],
        };

        let fixture_path = generate_fixture(temp_dir.path(), &config).expect("generate fixture");
        let roots = vec![fixture_path.clone()];

        group.bench_with_input(
            BenchmarkId::new("density_percent", density),
            &density,
            |b, _density| {
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

        let _ = cleanup_fixture(&fixture_path);
    }

    group.finish();
}

criterion_group!(benches, bench_directory_scale, bench_crypto_density);
criterion_main!(benches);
