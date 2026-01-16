use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::writer::MakeWriterExt;

const MAX_LOG_LINES: usize = 10_000;

#[derive(Clone)]
struct LineLimitedMakeWriter {
    path: PathBuf,
    max_lines: usize,
}

impl LineLimitedMakeWriter {
    fn new(path: impl Into<PathBuf>, max_lines: usize) -> Self {
        Self {
            path: path.into(),
            max_lines,
        }
    }
}

impl<'a> MakeWriter<'a> for LineLimitedMakeWriter {
    type Writer = LineLimitedFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LineLimitedFileWriter {
            path: self.path.clone(),
            max_lines: self.max_lines,
        }
    }
}

struct LineLimitedFileWriter {
    path: PathBuf,
    max_lines: usize,
}

impl Write for LineLimitedFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(buf)?;
        if buf.contains(&b'\n') {
            let _ = trim_file(&self.path, self.max_lines);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn trim_file(path: &Path, max_lines: usize) -> io::Result<()> {
    let mut contents = String::new();
    let mut file = File::open(path)?;
    file.read_to_string(&mut contents)?;
    let mut lines: Vec<&str> = contents.lines().collect();
    if lines.len() <= max_lines {
        return Ok(());
    }
    lines = lines.split_off(lines.len() - max_lines);
    let mut new_contents = lines.join("\n");
    new_contents.push('\n');
    std::fs::write(path, new_contents)?;
    Ok(())
}

pub fn init_logging(log_path: &str) {
    if let Err(error) = ensure_log_file(log_path) {
        eprintln!("failed to initialize log file {}: {}", log_path, error);
    }
    let file_writer = LineLimitedMakeWriter::new(log_path, MAX_LOG_LINES);
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stdout.and(file_writer))
        .init();

    tracing::info!(log_path, "logging initialized");
}

fn ensure_log_file(log_path: &str) -> io::Result<()> {
    let path = Path::new(log_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new().create(true).append(true).open(path)?;
    Ok(())
}
