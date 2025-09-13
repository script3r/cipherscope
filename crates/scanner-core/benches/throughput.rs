use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use scanner_core::*;
use std::path::PathBuf;
use std::sync::Arc;

fn bench_scan(c: &mut Criterion) {
    let patterns = include_str!("../../../patterns.toml");
    let reg = PatternRegistry::load(patterns).unwrap();
    let reg = Arc::new(reg);
    let dets: Vec<Box<dyn Detector>> = vec![
        Box::new(PatternDetector::new(
            "detector-go",
            &[Language::Go],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-java",
            &[Language::Java],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-c",
            &[Language::C],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-cpp",
            &[Language::Cpp],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-rust",
            &[Language::Rust],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-python",
            &[Language::Python],
            reg.clone(),
        )),
        Box::new(PatternDetector::new(
            "detector-php",
            &[Language::Php],
            reg.clone(),
        )),
    ];
    let scanner = Scanner::new(&reg, dets, Config::default());

    let root = PathBuf::from("../../fixtures");
    c.benchmark_group("scan")
        .throughput(Throughput::Bytes(10_000_000))
        .bench_function("fixtures", |b| {
            b.iter(|| {
                let _ = scanner.run(&[root.clone()]).unwrap();
            });
        });
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);
