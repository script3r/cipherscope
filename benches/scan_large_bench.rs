use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use tempfile::NamedTempFile;

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

fn bench_scan_large(c: &mut Criterion) {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let patterns_path = repo_root.join("patterns.toml");

    let default_fixture = repo_root
        .join("..")
        .join("cipherscope-paper")
        .join("fixture");
    let fixture_root = std::env::var_os("CIPHERSCOPE_BENCH_FIXTURE")
        .map(PathBuf::from)
        .unwrap_or(default_fixture);

    if !fixture_root.is_dir() {
        eprintln!(
            "Skipping scan_large bench: fixture root not found at {}",
            fixture_root.display()
        );
        return;
    }

    let roots = vec![fixture_root];

    let mut group = c.benchmark_group("scan_large");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(5));
    group.measurement_time(Duration::from_secs(30));

    let thread_counts: Vec<usize> = std::env::var("CIPHERSCOPE_BENCH_THREADS")
        .ok()
        .and_then(|value| {
            let parsed: Vec<usize> = value
                .split(',')
                .filter_map(|item| item.trim().parse::<usize>().ok())
                .collect();
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        })
        .unwrap_or_else(|| vec![1usize, num_cpus::get()]);
    for threads in thread_counts {
        group.bench_with_input(
            BenchmarkId::new("fixture", threads),
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
}

criterion_group!(benches, bench_scan_large);
criterion_main!(benches);
