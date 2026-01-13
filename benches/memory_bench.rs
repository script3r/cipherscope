//! Memory usage benchmarks.
//!
//! These benchmarks measure memory usage during scans. Requires extended mode.
//!
//! Run with: CIPHERSCOPE_BENCH_EXTENDED=1 cargo bench --bench memory_bench
//! (Skipped in normal mode to keep benchmarks fast)

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

/// Get peak memory usage of a child process on Linux
#[cfg(target_os = "linux")]
fn run_scan_with_memory(
    roots: &[PathBuf],
    threads: usize,
    patterns_path: &Path,
) -> (Duration, Option<u64>) {
    let output = NamedTempFile::new().expect("create temp output file");

    let start = Instant::now();
    let result = Command::new("/usr/bin/time")
        .arg("-v")
        .arg(assert_cmd::cargo::cargo_bin!("cipherscope"))
        .arg("--output")
        .arg(output.path())
        .arg("--threads")
        .arg(threads.to_string())
        .arg("--patterns")
        .arg(patterns_path)
        .args(roots.iter().flat_map(|r| vec!["--roots".into(), r.clone()]))
        .output()
        .expect("run cipherscope with time");

    let elapsed = start.elapsed();

    let stderr = String::from_utf8_lossy(&result.stderr);
    let peak_memory = stderr.lines().find_map(|line| {
        if line.contains("Maximum resident set size") {
            line.split_whitespace().last()?.parse::<u64>().ok()
        } else {
            None
        }
    });

    assert!(result.status.success(), "cipherscope should succeed");

    (elapsed, peak_memory)
}

#[cfg(not(target_os = "linux"))]
fn run_scan_with_memory(
    roots: &[PathBuf],
    threads: usize,
    patterns_path: &Path,
) -> (Duration, Option<u64>) {
    let output = NamedTempFile::new().expect("create temp output file");

    let start = Instant::now();
    let status = Command::new(assert_cmd::cargo::cargo_bin!("cipherscope"))
        .arg("--output")
        .arg(output.path())
        .arg("--threads")
        .arg(threads.to_string())
        .arg("--patterns")
        .arg(patterns_path)
        .args(roots.iter().flat_map(|r| vec!["--roots".into(), r.clone()]))
        .status()
        .expect("run cipherscope");

    let elapsed = start.elapsed();
    assert!(status.success(), "cipherscope should succeed");

    (elapsed, None)
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

/// Benchmark memory usage with varying file counts
fn bench_memory_scaling(c: &mut Criterion) {
    if !is_extended() {
        eprintln!("Skipping memory_bench (set CIPHERSCOPE_BENCH_EXTENDED=1 to enable)");
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let patterns_path = repo_root.join("patterns.toml");
    let temp_dir = TempDir::new().expect("create temp directory");

    let file_counts: Vec<usize> = vec![100, 500, 1000];

    let mut group = c.benchmark_group("memory_scaling");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    let threads = num_cpus::get();

    for count in file_counts {
        let config = FixtureConfig {
            file_count: count,
            file_size: 4096,
            crypto_density: 50,
            languages: vec!["python".to_string(), "c".to_string()],
        };

        eprintln!("Generating fixture with {} files...", count);
        let fixture_path = generate_fixture(temp_dir.path(), &config).expect("generate fixture");
        let roots = vec![fixture_path.clone()];

        // Run once to measure memory
        let (duration, peak_memory) = run_scan_with_memory(&roots, threads, &patterns_path);
        if let Some(mem_kb) = peak_memory {
            eprintln!(
                "  {} files: {} ms, peak memory: {:.2} MB",
                count,
                duration.as_millis(),
                mem_kb as f64 / 1024.0
            );
        }

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

criterion_group!(benches, bench_memory_scaling);
criterion_main!(benches);
