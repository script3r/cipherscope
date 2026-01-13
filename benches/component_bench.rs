//! Component isolation benchmarks.
//!
//! These benchmarks measure individual scanner components in isolation
//! to identify performance bottlenecks and optimization opportunities.
//!
//! Run with: cargo bench --bench component_bench
//! Extended mode: CIPHERSCOPE_BENCH_EXTENDED=1 cargo bench --bench component_bench

use std::path::PathBuf;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use cipherscope::DEFAULT_PATTERNS;
use cipherscope::patterns::{Language, PatternSet};
use cipherscope::scan::{
    find_algorithms, find_library_anchors, has_anchor_hint, language_from_path, parse,
};

mod fixture_generator;
use fixture_generator::CodeTemplates;

fn is_extended() -> bool {
    std::env::var("CIPHERSCOPE_BENCH_EXTENDED").is_ok()
}

/// Benchmark AST parsing across different languages
fn bench_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));

    // Core languages only in normal mode
    let languages: Vec<(&str, Language, String)> = if is_extended() {
        vec![
            (
                "python",
                Language::Python,
                CodeTemplates::python_crypto(10000),
            ),
            ("c", Language::C, CodeTemplates::c_openssl(10000)),
            ("java", Language::Java, CodeTemplates::java_jca(10000)),
            ("go", Language::Go, CodeTemplates::go_crypto(10000)),
            ("rust", Language::Rust, CodeTemplates::rust_crypto(10000)),
        ]
    } else {
        vec![
            (
                "python",
                Language::Python,
                CodeTemplates::python_crypto(10000),
            ),
            ("c", Language::C, CodeTemplates::c_openssl(10000)),
        ]
    };

    for (name, lang, content) in &languages {
        group.throughput(Throughput::Bytes(content.len() as u64));
        group.bench_with_input(BenchmarkId::new("lang", name), content, |b, content| {
            b.iter(|| {
                parse(*lang, content).expect("parse should succeed");
            });
        });
    }

    group.finish();
}

/// Benchmark parsing with varying file sizes
fn bench_parsing_sizes(c: &mut Criterion) {
    if !is_extended() {
        return;
    }

    let mut group = c.benchmark_group("parsing_sizes");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));

    let sizes = vec![1024, 10 * 1024, 100 * 1024];

    for size in sizes {
        let content = CodeTemplates::python_crypto(size);
        group.throughput(Throughput::Bytes(content.len() as u64));
        group.bench_with_input(BenchmarkId::new("bytes", size), &content, |b, content| {
            b.iter(|| {
                parse(Language::Python, content).expect("parse should succeed");
            });
        });
    }

    group.finish();
}

/// Benchmark anchor hint detection (fast regex pre-filter)
fn bench_anchor_hint(c: &mut Criterion) {
    let patterns = PatternSet::from_toml(DEFAULT_PATTERNS).expect("valid patterns");

    let mut group = c.benchmark_group("anchor_hint");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));

    // Test with crypto content (should match)
    let crypto_content = CodeTemplates::python_crypto(10000);
    group.throughput(Throughput::Bytes(crypto_content.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("match", "crypto"),
        &crypto_content,
        |b, content| {
            b.iter(|| {
                has_anchor_hint(Language::Python, content, &patterns);
            });
        },
    );

    // Test with non-crypto content (should not match)
    let non_crypto_content = "def hello():\n    print('world')\n".repeat(500);
    group.throughput(Throughput::Bytes(non_crypto_content.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("match", "no_crypto"),
        &non_crypto_content,
        |b, content| {
            b.iter(|| {
                has_anchor_hint(Language::Python, content, &patterns);
            });
        },
    );

    group.finish();
}

/// Benchmark library anchor detection
fn bench_library_anchors(c: &mut Criterion) {
    let patterns = PatternSet::from_toml(DEFAULT_PATTERNS).expect("valid patterns");

    let mut group = c.benchmark_group("library_anchors");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));

    let content = CodeTemplates::python_crypto(10000);
    let tree = parse(Language::Python, &content).expect("parse should succeed");

    group.throughput(Throughput::Bytes(content.len() as u64));
    group.bench_function("python", |b| {
        b.iter(|| {
            find_library_anchors(Language::Python, &content, &tree, &patterns);
        });
    });

    group.finish();
}

/// Benchmark algorithm detection
fn bench_algorithm_detection(c: &mut Criterion) {
    let patterns = PatternSet::from_toml(DEFAULT_PATTERNS).expect("valid patterns");

    let mut group = c.benchmark_group("algorithm_detection");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));

    let py_content = CodeTemplates::python_crypto(10000);
    let py_tree = parse(Language::Python, &py_content).expect("parse");
    let py_libs = find_library_anchors(Language::Python, &py_content, &py_tree, &patterns);

    if let Some(lib) = py_libs.first() {
        let lib_name = lib.library_name;
        group.throughput(Throughput::Bytes(py_content.len() as u64));
        group.bench_function("python", |b| {
            b.iter(|| {
                find_algorithms(Language::Python, &py_content, &py_tree, &patterns, lib_name);
            });
        });
    }

    group.finish();
}

/// Benchmark the full scan pipeline for a single file
fn bench_full_pipeline(c: &mut Criterion) {
    let patterns = PatternSet::from_toml(DEFAULT_PATTERNS).expect("valid patterns");

    let mut group = c.benchmark_group("full_pipeline");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));

    let content = CodeTemplates::python_crypto(10000);
    group.throughput(Throughput::Bytes(content.len() as u64));

    group.bench_function("python", |b| {
        b.iter(|| {
            if !has_anchor_hint(Language::Python, &content, &patterns) {
                return;
            }
            let tree = parse(Language::Python, &content).expect("parse");
            let lib_hits = find_library_anchors(Language::Python, &content, &tree, &patterns);
            for lib in lib_hits {
                find_algorithms(
                    Language::Python,
                    &content,
                    &tree,
                    &patterns,
                    lib.library_name,
                );
            }
        });
    });

    group.finish();
}

/// Benchmark language detection from file paths
fn bench_language_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("language_detection");
    group.sample_size(10);

    let paths = vec![
        PathBuf::from("/path/to/file.py"),
        PathBuf::from("/path/to/file.c"),
        PathBuf::from("/path/to/file.java"),
        PathBuf::from("/path/to/file.go"),
        PathBuf::from("/path/to/file.rs"),
    ];

    group.bench_function("extensions", |b| {
        b.iter(|| {
            for path in &paths {
                let _ = language_from_path(path);
            }
        });
    });

    group.finish();
}

/// Benchmark pattern set loading
fn bench_pattern_loading(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_loading");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));

    group.bench_function("default_patterns", |b| {
        b.iter(|| {
            PatternSet::from_toml(DEFAULT_PATTERNS).expect("valid patterns");
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parsing,
    bench_parsing_sizes,
    bench_anchor_hint,
    bench_library_anchors,
    bench_algorithm_detection,
    bench_full_pipeline,
    bench_language_detection,
    bench_pattern_loading
);
criterion_main!(benches);
