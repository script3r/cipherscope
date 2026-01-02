use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel as channel;
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use ignore::types::TypesBuilder;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use memmap2::Mmap;
use rayon::prelude::*;
use serde::Serialize;

mod patterns;
mod scan;

const DEFAULT_PATTERNS: &str = include_str!("../patterns.toml");

#[derive(Parser, Debug)]
#[command(
    name = "cipherscope",
    version,
    about = "Fast crypto inventory via static analysis"
)]
struct Cli {
    /// Root directory to scan
    #[arg(short, long, default_value = ".")]
    roots: Vec<PathBuf>,

    /// Exclude paths matching the given glob pattern
    #[arg(short, long)]
    exclude: Vec<String>,

    /// Path to patterns.toml (defaults to the embedded patterns)
    #[arg(short = 'p', long)]
    patterns: Option<PathBuf>,

    /// Output JSONL file path (defaults to stdout, use a filename to write to file)
    #[arg(short, long, default_value = "-")]
    output: String,

    /// Max parallelism
    #[arg(long, default_value_t = num_cpus::get())]
    threads: usize,

    /// Show progress bars
    #[arg(short = 'v', long)]
    progress: bool,

    /// Respect .gitignore files (enabled by default)
    #[arg(long, default_value = "true")]
    gitignore: bool,

    /// Skip files larger than this many megabytes
    #[arg(long, value_name = "MB", default_value = "1")]
    max_file_mb: Option<u64>,
}

#[derive(Serialize, Clone)]
struct Evidence {
    line: usize,
    column: usize,
}

#[derive(Serialize, Clone)]
struct Finding {
    #[serde(rename = "assetType")]
    asset_type: String,
    identifier: String,
    path: String,
    evidence: Evidence,
    #[serde(skip_serializing_if = "map_is_empty")]
    metadata: HashMap<String, serde_json::Value>,
}

fn map_is_empty(m: &HashMap<String, serde_json::Value>) -> bool {
    m.is_empty()
}

/// Main entry point for the scanner.
///
/// This function orchestrates the entire scanning process, which happens in two main phases:
/// 1.  **File Discovery**: It walks the filesystem to find all files that should be scanned,
///     applying filters based on file extensions and respecting ignore files. This is
///     done in parallel for performance.
/// 2.  **Scanning**: Each discovered file is then processed in a parallel rayon thread pool.
///     The `process_file` function handles the logic for parsing and scanning each file.
///
/// Findings are sent over a channel to a dedicated writer thread to avoid blocking the
/// scanning workers. Progress is reported to the console if requested.
fn main() -> Result<()> {
    let cli = Cli::parse();
    rayon::ThreadPoolBuilder::new()
        .num_threads(cli.threads)
        .build_global()
        .ok();

    let patterns_text = if let Some(path) = cli.patterns.as_ref() {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading patterns file: {}", path.display()))?
    } else {
        DEFAULT_PATTERNS.to_string()
    };
    let patterns = Arc::new(patterns::PatternSet::from_toml(&patterns_text)?);

    // Setup progress reporting
    let multi_progress = if cli.progress {
        Some(MultiProgress::new())
    } else {
        None
    };

    let file_count = Arc::new(AtomicUsize::new(0));
    let skipped_oversize_count = Arc::new(AtomicUsize::new(0));
    let scanned_count = Arc::new(AtomicUsize::new(0));
    let found_count = Arc::new(AtomicUsize::new(0));

    let discovery_bar = multi_progress.as_ref().map(|mp| {
        let pb = mp.add(ProgressBar::new_spinner());
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} Discovering files... {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        pb
    });

    let scan_bar = multi_progress.as_ref().map(|mp| {
        let pb = mp.add(ProgressBar::new(0));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({per_sec}) {msg}")
                .unwrap()
                .progress_chars("#>-")
        );
        pb
    });

    // Use an unbounded channel to avoid deadlocks
    // We'll rely on the file processing being the bottleneck, not the writer
    let (tx, rx) = channel::unbounded::<Finding>();
    let output_path = cli.output.clone();
    let found_count_writer = found_count.clone();
    let scan_bar_writer = scan_bar.clone();
    let writer_handle = std::thread::spawn(move || -> Result<()> {
        let mut writer: Box<dyn Write> = if output_path == "-" {
            Box::new(std::io::stdout())
        } else {
            let f =
                File::create(&output_path).with_context(|| format!("create {}", output_path))?;
            Box::new(BufWriter::new(f))
        };
        for finding in rx.iter() {
            serde_json::to_writer(&mut writer, &finding)?;
            writer.write_all(b"\n")?;
            let count = found_count_writer.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(pb) = &scan_bar_writer {
                pb.set_message(format!("Found {} cryptographic items", count));
            }
        }
        // Flush any remaining buffered output
        writer.flush()?;
        Ok(())
    });

    // First pass: collect files to scan
    let files_to_scan = Arc::new(std::sync::Mutex::new(Vec::new()));
    let patterns_for_discovery = patterns.clone();
    let file_count_discovery = file_count.clone();
    let skipped_oversize_discovery = skipped_oversize_count.clone();

    let mut walk_builder = WalkBuilder::new(&cli.roots[0]);
    if cli.roots.len() > 1 {
        for root in &cli.roots[1..] {
            walk_builder.add(root);
        }
    }

    let mut types_builder = TypesBuilder::new();
    types_builder.add("c", "*.c").unwrap();
    types_builder.add("c", "*.h").unwrap();
    types_builder.add("cpp", "*.cc").unwrap();
    types_builder.add("cpp", "*.cpp").unwrap();
    types_builder.add("cpp", "*.cxx").unwrap();
    types_builder.add("cpp", "*.hpp").unwrap();
    types_builder.add("cpp", "*.hh").unwrap();
    types_builder.add("cpp", "*.hxx").unwrap();
    types_builder.add("java", "*.java").unwrap();
    types_builder.add("python", "*.py").unwrap();
    types_builder.add("go", "*.go").unwrap();
    types_builder.add("swift", "*.swift").unwrap();
    types_builder.add("php", "*.php").unwrap();
    types_builder.add("php", "*.hack").unwrap();
    types_builder.add("objc", "*.m").unwrap();
    types_builder.add("objc", "*.mm").unwrap();
    types_builder.add("rust", "*.rs").unwrap();
    types_builder.select("c");
    types_builder.select("cpp");
    types_builder.select("java");
    types_builder.select("python");
    types_builder.select("go");
    types_builder.select("swift");
    types_builder.select("php");
    types_builder.select("objc");
    types_builder.select("rust");
    walk_builder.types(types_builder.build()?);

    if !cli.exclude.is_empty() {
        let mut override_builder = OverrideBuilder::new(Path::new("."));
        for pattern in &cli.exclude {
            override_builder.add(&format!("!{}", pattern))?;
        }
        let overrides = override_builder.build()?;
        walk_builder.overrides(overrides);
    }

    let max_bytes = cli.max_file_mb.map(|mb| mb.saturating_mul(1024 * 1024));

    walk_builder
        .hidden(false)
        .ignore(cli.gitignore)
        .git_ignore(cli.gitignore)
        .git_exclude(cli.gitignore)
        .git_global(cli.gitignore)
        .follow_links(false)
        .threads(cli.threads)
        .build_parallel()
        .run(|| {
            let patterns = patterns_for_discovery.clone();
            let files = files_to_scan.clone();
            let file_count = file_count_discovery.clone();
            let discovery_bar = discovery_bar.clone();
            let skipped_oversize = skipped_oversize_discovery.clone();
            Box::new(move |entry| {
                match entry {
                    Ok(e) if e.file_type().map(|t| t.is_file()).unwrap_or(false) => {
                        // Skip files larger than the configured limit (if any)
                        if let (Some(limit), Ok(meta)) = (max_bytes, e.metadata())
                            && meta.len() > limit
                        {
                            skipped_oversize.fetch_add(1, Ordering::Relaxed);
                            if let Some(pb) = &discovery_bar {
                                let found = file_count.load(Ordering::Relaxed);
                                let skipped = skipped_oversize.load(Ordering::Relaxed);
                                pb.set_message(format!(
                                    "Found {} files to scan (skipped {} oversized)",
                                    found, skipped
                                ));
                            }
                            return ignore::WalkState::Continue;
                        }

                        let path = e.path().to_path_buf();
                        if let Some(lang) = scan::language_from_path(&path)
                            && patterns.supports_language(lang)
                        {
                            files.lock().unwrap().push(path);
                            let count = file_count.fetch_add(1, Ordering::Relaxed) + 1;
                            if let Some(pb) = &discovery_bar {
                                let skipped = skipped_oversize.load(Ordering::Relaxed);
                                pb.set_message(format!(
                                    "Found {} files to scan (skipped {} oversized)",
                                    count, skipped
                                ));
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(err) => eprintln!("walk error: {err}"),
                }
                ignore::WalkState::Continue
            })
        });

    if let Some(pb) = &discovery_bar {
        pb.finish_with_message(format!(
            "Found {} files to scan (skipped {} oversized)",
            file_count.load(Ordering::Relaxed),
            skipped_oversize_count.load(Ordering::Relaxed)
        ));
    }

    // Second pass: scan files in parallel
    let files_to_scan = Arc::try_unwrap(files_to_scan)
        .unwrap()
        .into_inner()
        .unwrap();
    let total_files = files_to_scan.len();

    if let Some(pb) = &scan_bar {
        pb.set_length(total_files as u64);
        pb.set_message("Scanning files...");
    }

    // Process files in parallel with rayon
    files_to_scan.into_par_iter().for_each(|path| {
        // Process the file
        if let Err(err) = process_file(&path, &patterns, &tx) {
            eprintln!("Error processing {}: {err:#}", path.display());
        }

        scanned_count.fetch_add(1, Ordering::Relaxed);
        if let Some(pb) = &scan_bar {
            pb.inc(1);
        }
    });

    // All files have been processed
    drop(tx);

    if let Some(pb) = &scan_bar {
        pb.finish_with_message(format!(
            "Scanned {} files, found {} cryptographic items",
            scanned_count.load(Ordering::Relaxed),
            found_count.load(Ordering::Relaxed)
        ));
    }

    writer_handle.join().unwrap()?;

    if !cli.progress && cli.output != "-" {
        eprintln!(
            "Scanned {} files, found {} cryptographic items",
            scanned_count.load(Ordering::Relaxed),
            found_count.load(Ordering::Relaxed)
        );
    }

    Ok(())
}

/// Processes a single file to find cryptographic assets.
///
/// This function performs the core analysis for each file:
/// 1.  **Memory-maps** the file for efficient reading.
/// 2.  Decodes the file content to UTF-8, with a fallback to a lossy conversion.
/// 3.  **Parses** the content into an Abstract Syntax Tree (AST) using `tree-sitter`.
/// 4.  **Finds library anchors**: Scans the AST for `import` or `include` statements that
///     indicate the use of a known cryptographic library.
/// 5.  **Finds algorithms**: If a library is found, it then scans for specific algorithm
///     usage patterns (e.g., function calls, constants) associated with that library.
///
/// All findings are sent to the writer thread via a channel.
fn process_file(
    path: &Path,
    patterns: &patterns::PatternSet,
    tx: &channel::Sender<Finding>,
) -> Result<()> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file)? };
    // Decode file contents safely; fall back to lossy if not valid UTF-8 to avoid UB
    let content_owned;
    let content: &str = match std::str::from_utf8(&mmap) {
        Ok(s) => s,
        Err(_) => {
            content_owned = String::from_utf8_lossy(&mmap).into_owned();
            &content_owned
        }
    };

    // Avoid per-file canonicalize overhead; preserve original path for output
    let absolute_path = path.to_path_buf();

    let Some(lang) = scan::language_from_path(path) else {
        return Ok(());
    };
    if !scan::has_anchor_hint(lang, content, patterns) {
        return Ok(());
    }

    let tree = scan::parse(lang, content)?;

    // 1) library anchors
    let lib_hits = scan::find_library_anchors(lang, content, &tree, patterns);
    if lib_hits.is_empty() {
        return Ok(());
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut alg_hits_all = Vec::new();

    for lib in lib_hits {
        let evidence = Evidence {
            line: lib.line,
            column: lib.column,
        };
        let finding = Finding {
            asset_type: "library".to_string(),
            identifier: lib.library_name.to_string(),
            path: absolute_path.to_string_lossy().to_string(),
            evidence,
            metadata: HashMap::new(),
        };
        let key = format!("lib|{}", finding.identifier);
        if seen.insert(key) {
            // Use blocking send but log if it takes too long
            if let Err(e) = tx.send(finding) {
                eprintln!("error: writer thread has stopped: {}", e);
                return Ok(());
            }
        }

        // 2) algorithms for this library
        let alg_hits = scan::find_algorithms(lang, content, &tree, patterns, lib.library_name);
        alg_hits_all.extend(alg_hits);
    }

    let alg_hits_all = scan::dedupe_more_specific_hits(alg_hits_all);
    for alg in alg_hits_all {
        let mut metadata = HashMap::new();
        for (k, v) in alg.metadata {
            metadata.insert(k.to_string(), v);
        }
        let evidence = Evidence {
            line: alg.line,
            column: alg.column,
        };
        let finding = Finding {
            asset_type: "algorithm".to_string(),
            identifier: alg.algorithm_name.to_string(),
            path: absolute_path.to_string_lossy().to_string(),
            evidence,
            metadata,
        };
        let key = format!(
            "alg|{}|{}:{}",
            finding.identifier, finding.evidence.line, finding.evidence.column
        );
        if seen.insert(key) {
            // Use blocking send but log if it takes too long
            if let Err(e) = tx.send(finding) {
                eprintln!("error: writer thread has stopped: {}", e);
                return Ok(());
            }
        }
    }

    Ok(())
}
