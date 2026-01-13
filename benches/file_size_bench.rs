//! Benchmark for file size variation.
//!
//! This benchmark measures scanner performance across different file sizes.
//!
//! Run with: cargo bench --bench file_size_bench
//! Extended mode: CIPHERSCOPE_BENCH_EXTENDED=1 cargo bench --bench file_size_bench

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

fn bench_file_sizes(c: &mut Criterion) {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let patterns_path = repo_root.join("patterns.toml");
    let temp_dir = TempDir::new().expect("create temp directory");

    // Quick mode: 3 sizes, Extended mode: 5 sizes
    let sizes_kb: Vec<usize> = if is_extended() {
        vec![1, 10, 100, 500, 1024]
    } else {
        vec![1, 10, 100]
    };

    let mut group = c.benchmark_group("file_size");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    let threads = num_cpus::get();

    for size_kb in sizes_kb {
        let config = FixtureConfig {
            file_count: 5,
            file_size: size_kb * 1024,
            crypto_density: 100,
            languages: vec!["python".to_string(), "c".to_string()],
        };

        let fixture_path = generate_fixture(temp_dir.path(), &config).expect("generate fixture");
        let roots = vec![fixture_path.clone()];

        let total_bytes = (config.file_count * config.file_size) as u64;
        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(BenchmarkId::new("kb", size_kb), &size_kb, |b, _size_kb| {
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

criterion_group!(benches, bench_file_sizes);
criterion_main!(benches);
