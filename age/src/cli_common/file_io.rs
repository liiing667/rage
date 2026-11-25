//! File I/O helpers for CLI binaries.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use is_terminal::IsTerminal;
use zeroize::Zeroize;

use crate::{fl, util::LINE_ENDING, wfl, wlnfl};

const SHORT_OUTPUT_LENGTH: usize = 20 * 80;

#[derive(Debug)]
enum FileError {
    DenyBinaryOutput,
    DenyOverwriteFile(String),
    DetectedBinaryOutput,
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

/// A lazy [`File`] that is not opened until the first call to [`Write::write`] or
/// [`Write::flush`].
#[derive(Debug)]
pub struct LazyFile {
    filename: String,
    allow_overwrite: bool,
    #[cfg(unix)]
    mode: u32,
    file: Option<io::Result<File>>,
}

impl LazyFile {
    fn get_file(&mut self) -> io::Result<&mut File> {
        let filename = &self.filename;

        if self.file.is_none() {
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

            self.file = Some(options.open(filename));
        }

        self.file
            .as_mut()
            .unwrap()
            .as_mut()
            .map_err(|e| io::Error::new(e.kind(), format!("Failed to open file '{filename}'")))
    }
}

impl io::Write for LazyFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.get_file()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.get_file()?.flush()
    }
}

/// A file output that is only published after the caller explicitly commits it.
///
/// Plaintext is written to a uniquely-named temporary file in the same directory as
/// `destination`. Calling [`AtomicFile::finish`] flushes and syncs the spool before
/// atomically renaming it over `destination`. If the value is dropped before that point,
/// or [`AtomicFile::abort`] is called, the spool is removed and `destination` is left
/// untouched.
#[derive(Debug)]
pub struct AtomicFile {
    destination: PathBuf,
    temporary: PathBuf,
    file: Option<File>,
    mode: u32,
    committed: bool,
}

impl AtomicFile {
    /// Creates a new private spool next to `destination`.
    ///
    /// When replacing an existing destination, the destination's permissions are copied at
    /// commit time. New files use `mode` subject to the process umask.
    pub fn create(destination: impl Into<PathBuf>, mode: u32) -> io::Result<Self> {
        let destination = destination.into();
        let file_name = destination.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                FileError::InvalidFilename(destination.display().to_string()),
            )
        })?;
        let parent = destination
            .parent()
            .map(|p| {
                if p.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    p
                }
            })
            .unwrap_or_else(|| Path::new("."));

        if !parent.as_os_str().is_empty() && !parent.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                FileError::MissingDirectory(parent.display().to_string()),
            ));
        }

        static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
        let process_id = std::process::id();
        let file_name = file_name.to_string_lossy();

        for _ in 0..10_000 {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temporary = parent.join(format!(
                ".{file_name}.rage-spool-{process_id}-{counter}.tmp"
            ));

            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                // Keep the plaintext spool private until commit. Its final mode is set just
                // before the atomic rename.
                options.mode(0o600);
            }

            match options.open(&temporary) {
                Ok(file) => {
                    return Ok(Self {
                        destination,
                        temporary,
                        file: Some(file),
                        mode,
                        committed: false,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!(
                            "Failed to create temporary output file '{}': {e}",
                            temporary.display()
                        ),
                    ));
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary output file",
        ))
    }

    /// Returns the final destination path.
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Returns the not-yet-published spool path.
    pub fn temporary(&self) -> &Path {
        &self.temporary
    }

    /// Flushes, syncs, preserves existing permissions, and atomically publishes output.
    pub fn finish(mut self) -> io::Result<()> {
        let mut file = self.file.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "temporary output file is closed")
        })?;

        file.flush()?;

        // Preserve the explicit mode of an existing file. For a new file, the mode supplied
        // to `create` was already intersected with the umask by the kernel.
        #[cfg(unix)]
        {
            if let Ok(existing) = fs::metadata(&self.destination) {
                file.set_permissions(existing.permissions())?;
            } else {
                let parent = self
                    .temporary
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf();
                let mode = effective_create_mode(&parent, self.mode)?;
                file.set_permissions(fs::Permissions::from_mode(mode))?;
            }
        }
        #[cfg(not(unix))]
        let _ = &self.mode;

        file.sync_all()?;
        // Close the spool before renaming; this is required for reliable replacement on
        // platforms such as Windows and is harmless on Unix.
        drop(file);

        fs::rename(&self.temporary, &self.destination).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Failed to publish temporary output '{}' to '{}': {e}",
                    self.temporary.display(),
                    self.destination.display()
                ),
            )
        })?;
        self.committed = true;
        Ok(())
    }

    /// Discards the spool without touching the destination.
    pub fn abort(mut self) {
        self.committed = false;
        self.file = None;
        let _ = fs::remove_file(&self.temporary);
    }
}

#[cfg(unix)]
fn effective_create_mode(directory: &Path, requested: u32) -> io::Result<u32> {
    static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let path = directory.join(format!(
        ".rage-mode-probe-{}-{}.tmp",
        std::process::id(),
        PROBE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(requested)
        .open(&path)?;
    let mode = file.metadata()?.permissions().mode() & 0o7777;
    drop(file);
    let _ = fs::remove_file(&path);
    Ok(mode)
}

impl io::Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file
            .as_mut()
            .expect("AtomicFile used after close")
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()
        } else {
            Ok(())
        }
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if !self.committed {
            self.file = None;
            let _ = fs::remove_file(&self.temporary);
        }
    }
}

/// A private temporary spool used to withhold stdout until decryption is complete.
#[derive(Debug)]
pub struct TemporarySpool {
    path: PathBuf,
    file: Option<File>,
    committed: bool,
}

impl TemporarySpool {
    /// Creates a private spool in the current directory, falling back to `TMPDIR`.
    pub fn new() -> io::Result<Self> {
        Self::new_in(Path::new(".")).or_else(|first| {
            let temp_dir = std::env::temp_dir();
            Self::new_in(&temp_dir).map_err(|second| {
                io::Error::new(
                    second.kind(),
                    format!(
                        "could not create stdout spool in current directory ({first}) or {} ({second})",
                        temp_dir.display()
                    ),
                )
            })
        })
    }

    fn new_in(directory: &Path) -> io::Result<Self> {
        static SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);
        let process_id = std::process::id();

        for _ in 0..10_000 {
            let counter = SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(".rage-stdout-spool-{process_id}-{counter}.tmp"));
            let mut options = OpenOptions::new();
            options.write(true).read(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);

            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                        committed: false,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary spool",
        ))
    }

    /// Copies the complete, authenticated spool to the final stdout writer.
    pub fn publish_to<W: Write>(mut self, writer: &mut W) -> io::Result<u64> {
        let file = self.file.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "temporary spool is closed")
        })?;
        file.flush()?;
        file.seek(SeekFrom::Start(0))?;
        let copied = io::copy(file, writer)?;
        writer.flush()?;
        self.committed = true;
        Ok(copied)
    }
}

impl io::Write for TemporarySpool {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file
            .as_mut()
            .expect("TemporarySpool used after close")
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()
        } else {
            Ok(())
        }
    }
}

impl Drop for TemporarySpool {
    fn drop(&mut self) {
        self.file = None;
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        } else {
            // `publish_to` has already copied and flushed; unlink the now-closed path.
            let _ = fs::remove_file(&self.path);
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

                // We open the file lazily, but as we don't want the caller to assume
                // this, we eagerly confirm that the file does not exist if we can't
                // overwrite it.
                if !allow_overwrite && file_path.exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        FileError::DenyOverwriteFile(filename),
                    ));
                }

                return Ok(OutputWriter::File(LazyFile {
                    filename,
                    allow_overwrite,
                    #[cfg(unix)]
                    mode: _mode,
                    file: None,
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
    use super::{OutputFormat, OutputWriter};
    #[cfg(unix)]
    use std::io::Write;

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
        use std::io;

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
}
