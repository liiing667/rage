//! File I/O helpers for CLI binaries.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use is_terminal::IsTerminal;
use zeroize::Zeroize;

use crate::{fl, util::LINE_ENDING, wfl, wlnfl};

const SHORT_OUTPUT_LENGTH: usize = 20 * 80;

/// Marker embedded in the name of output files that are still being written.
///
/// A completed output is only ever published under its final name. While a file
/// transaction is in progress, bytes go to a hidden spool file next to the final
/// destination. The spool name deliberately carries this marker so that both readers and
/// writers can recognise (and reject) an unfinished output even if a process was killed
/// before it could clean up.
const SPOOL_MARKER: &str = ".rage-spool-";

static SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);

fn spool_path_for(destination: &str) -> PathBuf {
    let destination = Path::new(destination);
    let file_name = destination
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".to_owned());
    destination.with_file_name(format!(
        ".{file_name}{SPOOL_MARKER}{}-{}.tmp",
        std::process::id(),
        SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

fn is_spool_file_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    let Some(index) = rest.rfind(SPOOL_MARKER) else {
        return false;
    };
    if index == 0 {
        return false;
    }
    let Some(suffix) = rest[index + SPOOL_MARKER.len()..].strip_suffix(".tmp") else {
        return false;
    };
    let mut parts = suffix.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(pid), Some(counter), None)
            if !pid.is_empty()
                && !counter.is_empty()
                && pid.bytes().all(|b| b.is_ascii_digit())
                && counter.bytes().all(|b| b.is_ascii_digit())
    )
}

fn is_spool_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_spool_file_name)
}

fn spool_pid(name: &str) -> Option<u32> {
    let index = name.rfind(SPOOL_MARKER)?;
    let suffix = name[index + SPOOL_MARKER.len()..].strip_suffix(".tmp")?;
    suffix.split('-').next()?.parse().ok()
}

fn process_is_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Without a portable process-liveness probe, leave the artifact alone.
        let _ = pid;
        true
    }
}

/// Best-effort cleanup of spools left by processes that no longer exist.
///
/// The spool name carries the writer's PID. We only remove a spool for this exact
/// destination when that process is gone; a live concurrent writer is never disturbed.
fn cleanup_stale_spools(destination: &str) {
    let destination = Path::new(destination);
    let Some(file_name) = destination.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let prefix = format!(".{file_name}{SPOOL_MARKER}");
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with(&prefix) || !is_spool_file_name(&name) {
            continue;
        }
        let Some(pid) = spool_pid(&name) else {
            continue;
        };
        if pid != std::process::id() && !process_is_alive(pid) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn sync_parent_dir(destination: &str) {
    #[cfg(unix)]
    {
        let parent = Path::new(destination)
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = destination;
    }
}

#[derive(Debug)]
enum FileError {
    DenyBinaryOutput,
    DenyOverwriteFile(String),
    DetectedBinaryOutput,
    IncompleteOutput(String),
    InvalidFilename(String),
    MissingDirectory(String),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DenyBinaryOutput => {
                wlnfl!(f, "err-deny-binary-output")?;
                wfl!(f, "rec-deny-binary-output")
            }
            Self::DenyOverwriteFile(filename) => {
                wfl!(f, "err-deny-overwrite-file", filename = filename.as_str())
            }
            Self::DetectedBinaryOutput => {
                wlnfl!(f, "err-detected-binary")?;
                wfl!(f, "rec-detected-binary")
            }
            Self::IncompleteOutput(filename) => {
                wfl!(f, "err-incomplete-output", filename = filename.as_str())
            }
            Self::InvalidFilename(filename) => {
                wfl!(f, "err-invalid-filename", filename = filename.as_str())
            }
            Self::MissingDirectory(path) => wfl!(f, "err-missing-directory", path = path.as_str()),
        }
    }
}

impl std::error::Error for FileError {}

/// Wrapper around a [`File`].
pub struct FileReader {
    inner: File,
    filename: String,
}

/// Wrapper around either a file or standard input.
pub enum InputReader {
    /// Wrapper around a file.
    File(FileReader),
    /// Wrapper around standard input.
    Stdin(io::Stdin),
}

impl InputReader {
    /// Reads input from the given filename, or standard input if `None` or `Some("-")`.
    pub fn new(input: Option<String>) -> io::Result<Self> {
        if let Some(filename) = input {
            // Respect the Unix convention that "-" as an input filename
            // parameter is an explicit request to use standard input.
            if filename != "-" {
                // A spool file is an unfinished output transaction. Never let a
                // consumer reopen it as if it were a complete product.
                if is_spool_path(Path::new(&filename)) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        FileError::IncompleteOutput(filename),
                    ));
                }
                return Ok(InputReader::File(FileReader {
                    inner: File::open(&filename)?,
                    filename,
                }));
            }
        }

        Ok(InputReader::Stdin(io::stdin()))
    }

    /// Returns true if this input is from a terminal, and a user is likely typing it.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Stdin(_)) && io::stdin().is_terminal()
    }

    pub(crate) fn filename(&self) -> Option<&str> {
        if let Self::File(f) = self {
            Some(&f.filename)
        } else {
            None
        }
    }
}

impl Read for InputReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            InputReader::File(f) => f.inner.read(buf),
            InputReader::Stdin(handle) => handle.read(buf),
        }
    }
}

/// A stdout write that optionally buffers the entire output before writing.
#[derive(Debug)]
enum StdoutBuffer {
    Direct(io::Stdout),
    Buffered(Vec<u8>),
}

impl StdoutBuffer {
    fn direct() -> Self {
        Self::Direct(io::stdout())
    }

    fn buffered() -> Self {
        Self::Buffered(Vec::with_capacity(8 * 1024 * 1024))
    }
}

impl Write for StdoutBuffer {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            StdoutBuffer::Direct(w) => w.write(data),
            StdoutBuffer::Buffered(buf) => {
                // If we need to re-allocate the buffer, do so manually so we can zeroize.
                if buf.len() + data.len() > buf.capacity() {
                    let mut new_buf = Vec::with_capacity(std::cmp::max(
                        buf.capacity() * 2,
                        buf.capacity() + data.len(),
                    ));
                    new_buf.extend_from_slice(buf);
                    buf.zeroize();
                    *buf = new_buf;
                }

                buf.extend_from_slice(data);
                Ok(data.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            StdoutBuffer::Direct(w) => w.flush(),
            StdoutBuffer::Buffered(buf) => {
                let mut w = io::stdout();
                w.write_all(buf)?;
                buf.zeroize();
                buf.clear();
                w.flush()
            }
        }
    }
}

impl Drop for StdoutBuffer {
    fn drop(&mut self) {
        // Destructors should not panic, so we ignore a failed flush.
        let _ = self.flush();
    }
}

/// The data format being written out.
#[derive(Debug)]
pub enum OutputFormat {
    /// Binary data that should not be sent to a TTY by default.
    Binary,
    /// Text data that is acceptable to send to a TTY.
    Text,
    /// Unknown data format; try to avoid sending binary data to a TTY.
    Unknown,
}

/// Writer that wraps standard output to handle TTYs nicely.
#[derive(Debug)]
pub struct StdoutWriter {
    inner: StdoutBuffer,
    count: usize,
    format: OutputFormat,
    is_tty: bool,
    truncated: bool,
}

impl StdoutWriter {
    fn new(format: OutputFormat, is_tty: bool, input_is_tty: bool) -> Self {
        StdoutWriter {
            // If the input comes from a TTY and the output will go to a TTY, buffer the
            // output so it doesn't get in the way of typing the input.
            inner: if input_is_tty && is_tty {
                StdoutBuffer::buffered()
            } else {
                StdoutBuffer::direct()
            },
            count: 0,
            format,
            is_tty,
            truncated: false,
        }
    }
}

impl Write for StdoutWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.is_tty {
            if let OutputFormat::Unknown = self.format {
                // Don't send unprintable output to TTY
                if std::str::from_utf8(data).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        FileError::DetectedBinaryOutput,
                    ));
                }
            }

            let to_write = if let OutputFormat::Binary = self.format {
                // Only occurs if the user has explicitly forced stdout, so don't truncate.
                data.len()
            } else {
                // Drop output if we've truncated already, or need to.
                if self.truncated || self.count == SHORT_OUTPUT_LENGTH {
                    if !self.truncated {
                        self.inner.write_all(LINE_ENDING.as_bytes())?;
                        self.inner.write_all(b"[")?;
                        self.inner.write_all(fl!("cli-truncated-tty").as_bytes())?;
                        self.inner.write_all(b"]")?;
                        self.inner.write_all(LINE_ENDING.as_bytes())?;
                        self.truncated = true;
                    }

                    return io::sink().write(data);
                }

                let mut to_write = SHORT_OUTPUT_LENGTH - self.count;
                if to_write > data.len() {
                    to_write = data.len();
                }
                to_write
            };

            let mut ret = self.inner.write(&data[..to_write])?;
            self.count += to_write;

            if let OutputFormat::Binary = self.format {
                // Only occurs if the user has explicitly forced stdout, so don't truncate.
            } else {
                // If we have reached the output limit with data to spare,
                // truncate and drop the remainder.
                if self.count == SHORT_OUTPUT_LENGTH && data.len() > to_write {
                    if !self.truncated {
                        self.inner.write_all(LINE_ENDING.as_bytes())?;
                        self.inner.write_all(b"[")?;
                        self.inner.write_all(fl!("cli-truncated-tty").as_bytes())?;
                        self.inner.write_all(b"]")?;
                        self.inner.write_all(LINE_ENDING.as_bytes())?;
                        self.truncated = true;
                    }
                    ret += io::sink().write(&data[to_write..])?;
                }
            }

            Ok(ret)
        } else {
            self.inner.write(data)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A lazy file output that publishes a completed generation atomically.
///
/// For regular files, all bytes are written to a hidden spool next to the destination.
/// [`LazyFile::finish`] flushes, syncs, and atomically publishes the spool under the
/// destination name. Dropping the writer before `finish` (for example because
/// decryption/authentication failed, or because the process exited early) discards the
/// spool and leaves any old, complete generation untouched.
///
/// Non-regular destinations such as `/dev/null` or `/dev/stdout` are written directly,
/// because replacing them with a renamed regular file would change their meaning.
#[derive(Debug)]
pub struct LazyFile {
    filename: String,
    allow_overwrite: bool,
    reopened: bool,
    direct: bool,
    #[cfg(unix)]
    mode: u32,
    file: Option<io::Result<File>>,
    /// Planned spool path. It is filled in when the first write happens; a collision
    /// with an existing spool selects a new unique name.
    spool: Option<PathBuf>,
    committed: bool,
    bytes_written: u64,
}

impl LazyFile {
    fn open_direct(&self) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.write(true);
        if self.allow_overwrite {
            options.create(true).truncate(true);
        } else {
            // In addition to the check in `OutputWriter::new`, we enforce this at
            // file opening time to avoid a race condition with the file being
            // separately created between `OutputWriter` construction and usage.
            options.create_new(true);
        }

        #[cfg(unix)]
        options.mode(self.mode);

        options.open(&self.filename)
    }

    fn open_spool(&mut self) -> io::Result<File> {
        for _ in 0..10_000 {
            let spool = self
                .spool
                .clone()
                .unwrap_or_else(|| spool_path_for(&self.filename));
            self.spool = Some(spool.clone());

            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(self.mode);

            match options.open(&spool) {
                Ok(file) => return Ok(file),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    // A previous interrupted run left this spool behind. Never reuse
                    // it: choose a new name so we cannot append to an incomplete
                    // candidate.
                    self.spool = None;
                }
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary output file",
        ))
    }

    fn get_file(&mut self) -> io::Result<&mut File> {
        if self.file.is_none() {
            let file = if self.direct {
                self.open_direct()
            } else {
                self.open_spool()
            };
            self.file = Some(file);
        }

        let filename = &self.filename;
        self.file.as_mut().unwrap().as_mut().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Failed to open file '{filename}': {error}"),
            )
        })
    }

    /// Returns the final destination path.
    pub fn destination(&self) -> &str {
        &self.filename
    }

    /// Returns true if the destination existed when this writer was created.
    pub fn is_reopened(&self) -> bool {
        self.reopened
    }

    /// Returns the planned spool path for an atomic file output.
    pub fn spool_path(&self) -> Option<&Path> {
        self.spool.as_deref()
    }

    /// Returns true when this writer stages output in a spool before publishing.
    pub fn is_atomic(&self) -> bool {
        !self.direct
    }

    /// Flushes, syncs, and publishes the spool under the destination name.
    ///
    /// This is the completion boundary. If this method is not called, or if it returns
    /// an error, the destination is not replaced and the spool is discarded by `Drop`.
    pub fn finish(mut self) -> io::Result<u64> {
        let bytes_written = self.bytes_written;
        let direct = self.direct;
        let filename = self.filename.clone();

        {
            let file = self.get_file()?;
            file.flush()?;

            if !direct {
                // Preserve the explicit permissions of an existing destination. For a
                // new file, the mode requested at spool creation already had the umask
                // applied by the kernel.
                if let Ok(existing) = fs::metadata(&filename) {
                    if existing.is_file() {
                        file.set_permissions(existing.permissions())?;
                    }
                }
                file.sync_all()?;
            }
        }

        if direct {
            self.committed = true;
            return Ok(bytes_written);
        }

        let spool = self
            .spool
            .clone()
            .expect("spool path is set for atomic outputs");

        if self.allow_overwrite {
            fs::rename(&spool, &filename).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "Failed to publish output '{}' to '{}': {error}",
                        spool.display(),
                        filename
                    ),
                )
            })?;
        } else {
            publish_new(&spool, &filename)?;
        }

        self.committed = true;
        sync_parent_dir(&filename);
        Ok(bytes_written)
    }
}

fn publish_new(spool: &Path, destination: &str) -> io::Result<()> {
    // A hard link publishes the fully written inode atomically and, unlike rename,
    // cannot replace a file that appeared after `OutputWriter::new` checked the path.
    match fs::hard_link(spool, destination) {
        Ok(()) => {
            let _ = fs::remove_file(spool);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(io::Error::new(
            error.kind(),
            FileError::DenyOverwriteFile(destination.to_owned()),
        )),
        Err(_) => {
            // Some filesystems do not support hard links. Fall back to a checked
            // rename, which is still strictly better than writing the destination in
            // place: it never exposes a partially written file.
            if Path::new(destination).symlink_metadata().is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    FileError::DenyOverwriteFile(destination.to_owned()),
                ));
            }
            fs::rename(spool, destination)
        }
    }
}

impl io::Write for LazyFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.get_file()?.write(buf)?;
        self.bytes_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.get_file()?.flush()
    }
}

impl Drop for LazyFile {
    fn drop(&mut self) {
        if !self.committed {
            // Close before unlinking so this also works on platforms where an open
            // file cannot be removed.
            self.file = None;
            if let Some(spool) = self.spool.take() {
                let _ = fs::remove_file(spool);
            }
        }
    }
}

/// Wrapper around either a file or standard output.
#[derive(Debug)]
pub enum OutputWriter {
    /// Wrapper around a file.
    File(LazyFile),
    /// Wrapper around standard output.
    Stdout(StdoutWriter),
}

impl OutputWriter {
    /// Constructs a new `OutputWriter`.
    ///
    /// Writes to the file at path `output`, or standard output if `output` is `None` or
    /// `Some("-")`.
    ///
    /// If `allow_overwrite` is `true`, the file at path `output` will be overwritten if
    /// it exists. This option has no effect if `output` is `None` or `Some("-")`.
    pub fn new(
        output: Option<String>,
        allow_overwrite: bool,
        mut format: OutputFormat,
        _mode: u32,
        input_is_tty: bool,
    ) -> io::Result<Self> {
        let is_tty = console::user_attended();
        if let Some(filename) = output {
            // Respect the Unix convention that "-" as an output filename
            // parameter is an explicit request to use standard output.
            if filename != "-" {
                let file_path = Path::new(&filename);

                // Never reopen an unfinished spool as a final output. A spool file is
                // the durable marker of a transaction that has not reached its commit
                // boundary.
                if is_spool_path(file_path) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        FileError::IncompleteOutput(filename),
                    ));
                }

                // Provide a better error if the filename is invalid, or the directory
                // containing the file does not exist (we don't automatically create
                // directories).
                if let Some(dir_path) = file_path.parent() {
                    if !(dir_path == Path::new("") || dir_path.exists()) {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            FileError::MissingDirectory(dir_path.display().to_string()),
                        ));
                    }
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        FileError::InvalidFilename(filename),
                    ));
                }

                let reopened = file_path.symlink_metadata().is_ok();
                // Character devices, FIFOs, and similar destinations have meaning of
                // their own; atomically replacing them with a regular file would be
                // wrong. Regular files (including symlinks that resolve to regular
                // files) use the transactional spool.
                let direct = fs::metadata(file_path)
                    .map(|metadata| !metadata.is_file())
                    .unwrap_or(false);

                // We open the file lazily, but as we don't want the caller to assume
                // this, we eagerly confirm that the file does not exist if we can't
                // overwrite it.
                if !allow_overwrite && reopened {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        FileError::DenyOverwriteFile(filename),
                    ));
                }

                let spool = if direct {
                    None
                } else {
                    cleanup_stale_spools(&filename);
                    Some(spool_path_for(&filename))
                };

                return Ok(OutputWriter::File(LazyFile {
                    filename,
                    allow_overwrite,
                    reopened,
                    direct,
                    #[cfg(unix)]
                    mode: _mode,
                    file: None,
                    spool,
                    committed: false,
                    bytes_written: 0,
                }));
            } else {
                // User explicitly requested stdout; force the format to binary so that we
                // don't try to parse it as UTF-8 in StdoutWriter and perhaps reject it.
                format = OutputFormat::Binary;
            }
        } else if is_tty {
            if let OutputFormat::Binary = format {
                // If output == Some("-") then this error is skipped.
                return Err(io::Error::other(FileError::DenyBinaryOutput));
            }
        }

        Ok(OutputWriter::Stdout(StdoutWriter::new(
            format,
            is_tty,
            input_is_tty,
        )))
    }

    /// Returns true if this output is to a terminal, and a user will likely see it.
    pub fn is_terminal(&self) -> bool {
        match self {
            OutputWriter::File(..) => false,
            OutputWriter::Stdout(w) => w.is_tty,
        }
    }

    /// Returns the final output path, or `None` when writing to standard output.
    pub fn file_path(&self) -> Option<&str> {
        match self {
            OutputWriter::File(file) => Some(file.destination()),
            OutputWriter::Stdout(_) => None,
        }
    }

    /// Returns true if a file destination existed when this writer was created.
    pub fn is_reopened(&self) -> bool {
        match self {
            OutputWriter::File(file) => file.is_reopened(),
            OutputWriter::Stdout(_) => false,
        }
    }

    /// Returns the spool path used by an atomic file output.
    pub fn spool_path(&self) -> Option<&Path> {
        match self {
            OutputWriter::File(file) => file.spool_path(),
            OutputWriter::Stdout(_) => None,
        }
    }

    /// Returns true when file output is staged and published atomically.
    pub fn is_atomic_file(&self) -> bool {
        match self {
            OutputWriter::File(file) => file.is_atomic(),
            OutputWriter::Stdout(_) => false,
        }
    }

    /// Completes a file output transaction.
    ///
    /// For a file this publishes the fully written generation under the destination
    /// name. For standard output it only flushes the pipe. Callers must invoke this
    /// after the complete operation has succeeded; dropping the writer without calling
    /// `finish` discards the file spool and leaves the previous generation untouched.
    pub fn finish(self) -> io::Result<u64> {
        match self {
            OutputWriter::File(file) => file.finish(),
            OutputWriter::Stdout(mut stdout) => {
                stdout.flush()?;
                Ok(0)
            }
        }
    }
}

impl Write for OutputWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            OutputWriter::File(f) => f.write(data),
            OutputWriter::Stdout(handle) => handle.write(data),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            OutputWriter::File(f) => f.flush(),
            OutputWriter::Stdout(handle) => handle.flush(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(unix)]
    use super::{InputReader, OutputFormat, OutputWriter};
    #[cfg(unix)]
    use std::{
        fs,
        io::{self, Write},
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[cfg(unix)]
    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let path = std::env::temp_dir().join(format!(
            "rage-output-transaction-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn lazy_existing_file_allow_overwrite() {
        OutputWriter::new(
            Some("/dev/null".to_string()),
            true,
            OutputFormat::Text,
            0o600,
            false,
        )
        .unwrap()
        .flush()
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lazy_existing_file_forbid_overwrite() {
        let e = OutputWriter::new(
            Some("/dev/null".to_string()),
            false,
            OutputFormat::Text,
            0o600,
            false,
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_output_is_only_published_on_finish() {
        let dir = temp_dir();
        let path = dir.join("out.bin");
        fs::write(&path, b"old complete generation").unwrap();
        let old_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;

        let mut output = OutputWriter::new(
            Some(path.display().to_string()),
            true,
            OutputFormat::Binary,
            0o600,
            false,
        )
        .unwrap();
        output.write_all(b"new complete generation").unwrap();

        // The destination is still the old generation while the transaction is open.
        assert_eq!(fs::read(&path).unwrap(), b"old complete generation");

        output.finish().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new complete generation");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            old_mode
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn aborted_output_preserves_old_generation_and_removes_spool() {
        let dir = temp_dir();
        let path = dir.join("out.bin");
        fs::write(&path, b"old complete generation").unwrap();

        let mut output = OutputWriter::new(
            Some(path.display().to_string()),
            true,
            OutputFormat::Binary,
            0o600,
            false,
        )
        .unwrap();
        output.write_all(b"unfinished plaintext").unwrap();
        let spool = output.spool_path().unwrap().to_path_buf();
        assert!(spool.exists());

        drop(output);

        assert_eq!(fs::read(&path).unwrap(), b"old complete generation");
        assert!(!spool.exists());

        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn new_output_is_published_with_the_requested_mode() {
        let dir = temp_dir();
        let path = dir.join("new.bin");

        let mut output = OutputWriter::new(
            Some(path.display().to_string()),
            false,
            OutputFormat::Binary,
            0o600,
            false,
        )
        .unwrap();
        output.write_all(b"new generation").unwrap();
        output.finish().unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new generation");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unfinished_spool_is_rejected_by_public_file_consumers() {
        let dir = temp_dir();
        let spool = dir.join(".out.bin.rage-spool-1234-0.tmp");
        fs::write(&spool, b"unfinished").unwrap();

        let input_error = match InputReader::new(Some(spool.display().to_string())) {
            Ok(_) => panic!("InputReader accepted an unfinished spool"),
            Err(error) => error,
        };
        assert_eq!(input_error.kind(), io::ErrorKind::InvalidData);

        let output_error = OutputWriter::new(
            Some(spool.display().to_string()),
            true,
            OutputFormat::Binary,
            0o600,
            false,
        )
        .unwrap_err();
        assert_eq!(output_error.kind(), io::ErrorKind::InvalidInput);

        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_spool_from_a_dead_process_is_cleaned_on_reopen() {
        let dir = temp_dir();
        let path = dir.join("out.bin");
        let stale = dir.join(".out.bin.rage-spool-4294967295-0.tmp");
        fs::write(&stale, b"left by a killed process").unwrap();

        let mut output = OutputWriter::new(
            Some(path.display().to_string()),
            true,
            OutputFormat::Binary,
            0o600,
            false,
        )
        .unwrap();
        assert!(!stale.exists(), "stale spool was not cleaned up");

        output.write_all(b"new generation").unwrap();
        output.finish().unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new generation");

        fs::remove_dir_all(dir).unwrap();
    }
}
