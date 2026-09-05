use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use cipherscope::{DEFAULT_PATTERNS, Finding, patterns, scan, scan_with_patterns};
use clap::Parser;
use crossbeam_channel as channel;
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tempfile::NamedTempFile;

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
    #[arg(long, default_value_t = default_thread_count(), value_parser = parse_thread_count)]
    threads: usize,

    /// Show progress bars
    #[arg(short = 'v', long)]
    progress: bool,

    /// Respect .gitignore files (enabled by default)
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        value_name = "BOOL"
    )]
    gitignore: bool,

    /// Skip files larger than this many megabytes
    #[arg(long, value_name = "MB", default_value = "1")]
    max_file_mb: Option<u64>,
}

fn default_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

fn parse_thread_count(value: &str) -> std::result::Result<usize, String> {
    let threads = value
        .parse::<usize>()
        .map_err(|_| "thread count must be a positive integer".to_string())?;
    if threads == 0 {
        return Err("thread count must be at least 1".to_string());
    }
    Ok(threads)
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
        .context("configure scanner thread pool")?;

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

    // Bounded queues apply backpressure when discovery or scanning outruns its consumer.
    let queue_capacity = cli.threads.saturating_mul(4).max(1);
    let (tx, rx) = channel::bounded::<Finding>(queue_capacity);
    // Streaming architecture: WalkBuilder sends files to channel, rayon workers process immediately
    // This eliminates the mutex contention and synchronous barrier of collect-then-process
    let (file_tx, file_rx) = channel::bounded::<PathBuf>(queue_capacity);
    let patterns_for_discovery = patterns.clone();
    let file_count_discovery = file_count.clone();
    let skipped_oversize_discovery = skipped_oversize_count.clone();

    let mut walk_builder = WalkBuilder::new(&cli.roots[0]);
    if cli.roots.len() > 1 {
        for root in &cli.roots[1..] {
            walk_builder.add(root);
        }
    }

    // language_from_path is the single source of truth for supported extensions.
    // A second, case-sensitive glob allowlist used to silently drop uppercase files.

    if !cli.exclude.is_empty() {
        let mut override_builder = OverrideBuilder::new(Path::new("."));
        for pattern in &cli.exclude {
            override_builder.add(&format!("!{}", pattern))?;
        }
        let overrides = override_builder.build()?;
        walk_builder.overrides(overrides);
    }

    let max_bytes = cli.max_file_mb.map(|mb| mb.saturating_mul(1024 * 1024));

    // Validate all options before opening output or starting background threads.
    let (writer, pending_output, output_scan_path) = prepare_output(&cli)?;
    let error_count = Arc::new(AtomicUsize::new(0));
    let cancelled = Arc::new(AtomicBool::new(false));
    let found_count_writer = found_count.clone();
    let scan_bar_writer = scan_bar.clone();
    let cancelled_writer = cancelled.clone();
    let writer_handle = std::thread::spawn(move || {
        let result = write_findings(writer, rx, &found_count_writer, scan_bar_writer.as_ref());
        if result.is_err() {
            cancelled_writer.store(true, Ordering::Relaxed);
        }
        result
    });

    // Spawn scanner workers that process files as they're discovered
    let scan_bar_for_workers = scan_bar.clone();
    let scanned_count_for_workers = scanned_count.clone();
    let patterns_for_workers = patterns.clone();
    let tx_for_workers = tx.clone();
    let errors_for_workers = error_count.clone();
    let cancelled_workers = cancelled.clone();
    let skipped_for_workers = skipped_oversize_count.clone();

    // Use a thread to run the parallel scanner on the receiving end
    let scanner_handle = std::thread::spawn(move || {
        // Process files as they arrive from the channel
        file_rx.into_iter().par_bridge().for_each(|path| {
            if cancelled_workers.load(Ordering::Relaxed) {
                return;
            }
            match process_file(&path, &patterns_for_workers, &tx_for_workers, max_bytes) {
                Ok(false) => {
                    skipped_for_workers.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Ok(true) => {}
                Err(err) => {
                    errors_for_workers.fetch_add(1, Ordering::Relaxed);
                    eprintln!("Error processing {}: {err:#}", path.display());
                }
            }

            scanned_count_for_workers.fetch_add(1, Ordering::Relaxed);
            if let Some(pb) = &scan_bar_for_workers {
                pb.inc(1);
            }
        });
    });

    // Walk and send files to channel (no mutex contention!)
    walk_builder
        .hidden(false)
        .ignore(cli.gitignore)
        .git_ignore(cli.gitignore)
        .git_exclude(cli.gitignore)
        .git_global(cli.gitignore)
        .follow_links(false)
        .skip_stdout(true)
        .threads(cli.threads)
        .build_parallel()
        .run(|| {
            let patterns = patterns_for_discovery.clone();
            let file_tx = file_tx.clone();
            let file_count = file_count_discovery.clone();
            let discovery_bar = discovery_bar.clone();
            let skipped_oversize = skipped_oversize_discovery.clone();
            let output_scan_path = output_scan_path.clone();
            let errors = error_count.clone();
            let cancelled = cancelled.clone();
            Box::new(move |entry| {
                if cancelled.load(Ordering::Relaxed) {
                    return ignore::WalkState::Quit;
                }
                if let Ok(entry) = &entry
                    && let Some(err) = entry.error()
                {
                    errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!("walk error: {err}");
                }
                match entry {
                    Ok(e) if e.file_type().map(|t| t.is_file()).unwrap_or(false) => {
                        // Never scan the output while it is being written, even if it has a
                        // supported source extension and lives below a requested root.
                        if output_scan_path.as_ref().is_some_and(|output| {
                            e.path().file_name() == output.file_name()
                                && e.path().canonicalize().is_ok_and(|path| path == *output)
                        }) {
                            return ignore::WalkState::Continue;
                        }

                        // Skip files larger than the configured limit (if any)
                        if let (Some(limit), Ok(meta)) = (max_bytes, e.metadata())
                            && meta.len() > limit
                        {
                            skipped_oversize.fetch_add(1, Ordering::Relaxed);
                            return ignore::WalkState::Continue;
                        }

                        let path = e.path().to_path_buf();
                        if let Some(lang) = scan::language_from_path(&path)
                            && patterns.supports_language(lang)
                        {
                            // Send to channel instead of pushing to mutex-protected Vec
                            if file_tx.send(path).is_err() {
                                return ignore::WalkState::Quit;
                            }
                            let count = file_count.fetch_add(1, Ordering::Relaxed) + 1;
                            // Batch progress updates: only update every 100 files
                            if let Some(pb) = &discovery_bar
                                && (count.is_multiple_of(100) || count == 1)
                            {
                                let skipped = skipped_oversize.load(Ordering::Relaxed);
                                pb.set_message(format!(
                                    "Found {} files to scan (skipped {} oversized)",
                                    count, skipped
                                ));
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                        eprintln!("walk error: {err}");
                    }
                }
                ignore::WalkState::Continue
            })
        });

    // Discovery complete - close the channel so scanners know to finish
    drop(file_tx);

    let total_files = file_count.load(Ordering::Relaxed);
    if let Some(pb) = &discovery_bar {
        pb.finish_with_message(format!(
            "Found {} files to scan (skipped {} oversized)",
            total_files,
            skipped_oversize_count.load(Ordering::Relaxed)
        ));
    }

    if let Some(pb) = &scan_bar {
        pb.set_length(total_files as u64);
        pb.set_message("Scanning files...");
    }

    // Wait for all scanning to complete
    let scanner_result = scanner_handle
        .join()
        .map_err(|_| anyhow!("scanner thread panicked"));

    // All files have been processed
    drop(tx);

    let writer_result = writer_handle
        .join()
        .map_err(|_| anyhow!("writer thread panicked"));
    scanner_result?;
    writer_result??;

    let errors = error_count.load(Ordering::Relaxed);
    if errors != 0 {
        bail!("scan incomplete: {errors} error(s); see diagnostics above");
    }
    if let Some(output) = pending_output {
        output
            .persist(&cli.output)
            .with_context(|| format!("save output: {}", cli.output))?;
    }

    if let Some(pb) = &scan_bar {
        pb.finish_with_message(format!(
            "Scanned {} files, found {} cryptographic items",
            scanned_count.load(Ordering::Relaxed),
            found_count.load(Ordering::Relaxed)
        ));
    }

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
/// 1.  Reads the file into owned memory, enforcing the size limit while reading.
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
    max_bytes: Option<u64>,
) -> Result<bool> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let Some(bytes) = read_source(file, max_bytes)? else {
        return Ok(false);
    };
    let content = String::from_utf8_lossy(&bytes);

    let Some(lang) = scan::language_from_path(path) else {
        return Ok(true);
    };
    let source_label = path.to_string_lossy();
    for finding in scan_with_patterns(&content, lang, &source_label, patterns)? {
        tx.send(finding).context("writer thread stopped")?;
    }

    Ok(true)
}

// Reading owned bytes avoids the undefined behavior of file-backed mmap when
// editors or build tools modify/truncate source files during a scan.
fn read_source(reader: impl Read, max_bytes: Option<u64>) -> Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    reader
        .take(max_bytes.unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .context("read source")?;
    if max_bytes.is_some_and(|limit| bytes.len() as u64 > limit) {
        return Ok(None);
    }
    Ok(Some(bytes))
}

type PreparedOutput = (
    Box<dyn Write + Send>,
    Option<NamedTempFile>,
    Option<PathBuf>,
);

fn prepare_output(cli: &Cli) -> Result<PreparedOutput> {
    if cli.output == "-" {
        return Ok((Box::new(BufWriter::new(std::io::stdout())), None, None));
    }
    let destination = Path::new(&cli.output);
    let existing = match std::fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if !metadata.is_file() {
                bail!("output must be a regular file: {}", destination.display());
            }
            let resolved = destination.canonicalize()?;
            let is_input = scan::language_from_path(destination).is_some()
                || cli
                    .roots
                    .iter()
                    .chain(cli.patterns.iter())
                    .any(|path| path.canonicalize().is_ok_and(|path| path == resolved));
            if is_input {
                bail!(
                    "refusing to overwrite scan input: {}",
                    destination.display()
                );
            }
            Some(resolved)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err).context("inspect output path"),
    };
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let pending = tempfile::Builder::new()
        .prefix(".cipherscope-")
        .suffix(".tmp")
        .tempfile_in(parent)
        .with_context(|| format!("create output in {}", parent.display()))?;
    let writer = BufWriter::new(pending.reopen()?);
    Ok((Box::new(writer), Some(pending), existing))
}

fn write_findings(
    mut writer: impl Write,
    rx: channel::Receiver<Finding>,
    found_count: &AtomicUsize,
    progress: Option<&ProgressBar>,
) -> Result<()> {
    for finding in rx {
        serde_json::to_writer(&mut writer, &finding)?;
        writer.write_all(b"\n")?;
        let count = found_count.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(pb) = progress {
            pb.set_message(format!("Found {count} cryptographic items"));
        }
    }
    writer.flush().context("flush findings")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_at_most_limit_plus_one_bytes() {
        let mut reader = std::io::Cursor::new(vec![b'x'; 100]);
        assert!(read_source(&mut reader, Some(8)).unwrap().is_none());
        assert_eq!(reader.position(), 9);
        assert_eq!(
            read_source(&b"abcd"[..], Some(4)).unwrap().unwrap(),
            b"abcd"
        );
        assert!(read_source(&b""[..], Some(0)).unwrap().unwrap().is_empty());
    }

    #[test]
    fn writer_propagates_flush_failure() {
        struct FailingFlush;
        impl Write for FailingFlush {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("disk full"))
            }
        }
        let (tx, rx) = channel::bounded(1);
        drop(tx);
        let error = write_findings(FailingFlush, rx, &AtomicUsize::new(0), None).unwrap_err();
        assert!(format!("{error:#}").contains("disk full"));
    }
}
