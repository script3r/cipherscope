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

fn bench_scan(c: &mut Criterion) {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let patterns_path = repo_root.join("patterns.toml");

    let fixtures = vec![repo_root.join("fixtures")];
    let repo_mix = vec![
        repo_root.join("fixtures"),
        repo_root.join("src"),
        repo_root.join("tests"),
    ];

    let mut group = c.benchmark_group("scan");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    let thread_counts = [1usize, num_cpus::get()];
    for threads in thread_counts {
        group.bench_with_input(
            BenchmarkId::new("fixtures", threads),
            &threads,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        run_scan(&fixtures, threads, &patterns_path);
                        total += start.elapsed();
                    }
                    total
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("repo_mix", threads),
            &threads,
            |b, &threads| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        run_scan(&repo_mix, threads, &patterns_path);
                        total += start.elapsed();
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);
