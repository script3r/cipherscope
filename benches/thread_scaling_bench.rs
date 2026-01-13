//! Benchmark for thread scaling analysis.
//!
//! This benchmark measures how scanner performance scales with thread count.
//!
//! Run with: cargo bench --bench thread_scaling_bench
//! Extended mode: CIPHERSCOPE_BENCH_EXTENDED=1 cargo bench --bench thread_scaling_bench

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
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

fn bench_thread_scaling(c: &mut Criterion) {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let patterns_path = repo_root.join("patterns.toml");
    let temp_dir = TempDir::new().expect("create temp directory");

    // Generate a fixture for thread scaling tests
    let file_count = if is_extended() { 1000 } else { 500 };
    let config = FixtureConfig {
        file_count,
        file_size: 4096,
        crypto_density: 50,
        languages: vec!["python".to_string(), "c".to_string(), "java".to_string()],
    };

    eprintln!(
        "Generating fixture with {} files for thread scaling...",
        config.file_count
    );
    let fixture_path = generate_fixture(temp_dir.path(), &config).expect("generate fixture");
    let roots = vec![fixture_path.clone()];

    // Thread counts to test
    let max_cpus = num_cpus::get();
    let thread_counts: Vec<usize> = if is_extended() {
        vec![1, 2, 4, 8, 16, 32, 64]
            .into_iter()
            .filter(|&t| t <= max_cpus)
            .collect()
    } else {
        vec![1, max_cpus / 2, max_cpus]
            .into_iter()
            .filter(|&t| t > 0 && t <= max_cpus)
            .collect()
    };

    let mut group = c.benchmark_group("thread_scaling");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    for threads in &thread_counts {
        group.bench_with_input(
            BenchmarkId::new("threads", threads),
            threads,
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

criterion_group!(benches, bench_thread_scaling);
criterion_main!(benches);
