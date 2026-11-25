//! File I/O helpers for CLI binaries.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

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
    RefuseSymlinkOutput(String),
    TargetIdentityChanged(String),
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
            Self::RefuseSymlinkOutput(filename) => {
                wfl!(f, "err-refuse-symlink-output", filename = filename.as_str())
            }
            Self::TargetIdentityChanged(filename) => wfl!(
                f,
                "err-output-target-identity-changed",
                filename = filename.as_str()
            ),
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

/// The stable identity of a checked output target.
///
/// On Unix this is the `(st_dev, st_ino)` pair. The owned [`File`] remains bound
/// to that object even if a path component is renamed or replaced later.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    unsupported: (),
}

impl FileIdentity {
    #[cfg(unix)]
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[cfg(not(unix))]
    fn from_metadata(_metadata: &fs::Metadata) -> Self {
        Self { unsupported: () }
    }

    fn of_file(file: &File) -> io::Result<Self> {
        Ok(Self::from_metadata(&file.metadata()?))
    }

    fn at_path(path: &Path) -> io::Result<Self> {
        Ok(Self::from_metadata(&fs::metadata(path)?))
    }
}

/// An opened [`File`] together with the identity it was checked against.
#[derive(Debug)]
struct BoundFile {
    inner: File,
    identity: FileIdentity,
}

impl BoundFile {
    /// Ensure the visible path still resolves to the exact object bound to
    /// this writer.
    ///
    /// The actual writes always use the owned file descriptor, so a losing race
    /// cannot redirect bytes. This check additionally turns a deterministic
    /// post-check replacement into an explicit closed failure.
    fn verify_path(&self, filename: &str) -> io::Result<()> {
        let current = FileIdentity::at_path(Path::new(filename)).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                identity_changed_error(filename)
            } else {
                error
            }
        })?;

        if current != self.identity {
            return Err(identity_changed_error(filename));
        }

        Ok(())
    }
}

fn symlink_output_error(filename: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        FileError::RefuseSymlinkOutput(filename.to_owned()),
    )
}

fn identity_changed_error(filename: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        FileError::TargetIdentityChanged(filename.to_owned()),
    )
}

/// The final path component observed by [`OutputWriter::new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckedTarget {
    /// The path did not exist; opening must claim it with `O_CREAT | O_EXCL`.
    Absent,
    /// The final component was a symlink; consumption must fail closed.
    Symlink,
    /// A non-symlink object with an identity bound to the eventual descriptor.
    Identity(FileIdentity),
}

/// Check the final path component without following an unexamined symlink.
fn check_output_path(file_path: &Path) -> io::Result<CheckedTarget> {
    let metadata = match fs::symlink_metadata(file_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(CheckedTarget::Absent),
        Err(error) => return Err(error),
    };

    if metadata.file_type().is_symlink() {
        return Ok(CheckedTarget::Symlink);
    }

    Ok(CheckedTarget::Identity(FileIdentity::from_metadata(
        &metadata,
    )))
}

/// A lazy [`File`] that is not opened until the first call to [`Write::write`] or
/// [`Write::flush`].
#[derive(Debug)]
pub struct LazyFile {
    filename: String,
    allow_overwrite: bool,
    /// Path state and identity checked in [`OutputWriter::new`].
    checked_target: CheckedTarget,
    #[cfg(unix)]
    mode: u32,
    file: Option<io::Result<BoundFile>>,
}

impl LazyFile {
    fn open_checked(&self) -> io::Result<BoundFile> {
        let mut options = OpenOptions::new();
        options.write(true);

        let expected_identity = match self.checked_target {
            CheckedTarget::Symlink => return Err(symlink_output_error(&self.filename)),
            CheckedTarget::Absent => None,
            CheckedTarget::Identity(identity) => Some(identity),
        };

        if !self.allow_overwrite || expected_identity.is_none() {
            // `create_new` is atomic: it claims an absent path and rejects a
            // file or symlink inserted after the constructor check.
            options.create_new(true);
        } else {
            // Open the constructor-checked existing object without `O_TRUNC`
            // or `O_CREAT`. We verify the identity before destroying its
            // contents, and never create through a swapped dangling link.
            options.create(false).truncate(false);
        }

        #[cfg(unix)]
        options.mode(self.mode);

        let file = options.open(&self.filename)?;
        let identity = FileIdentity::of_file(&file)?;

        if let Some(expected_identity) = expected_identity {
            if identity != expected_identity {
                return Err(identity_changed_error(&self.filename));
            }

            // Truncate only after the open descriptor is proven to point at
            // the constructor-checked object. Skip non-regular targets such
            // as `/dev/null`, where `ftruncate` is not meaningful.
            if file.metadata()?.is_file() {
                file.set_len(0)?;
            }
        }

        Ok(BoundFile {
            inner: file,
            identity,
        })
    }

    fn get_file(&mut self) -> io::Result<&mut File> {
        let filename = &self.filename;

        if self.file.is_none() {
            self.file = Some(self.open_checked());
        }

        let bound = self.file.as_mut().unwrap().as_mut().map_err(|e| {
            io::Error::new(e.kind(), format!("Failed to open file '{filename}': {e}"))
        })?;

        // If the path was replaced after the previous successful check, fail
        // closed before the next write. The owned descriptor remains bound to
        // the checked identity regardless of this path-based verification.
        bound.verify_path(filename)?;

        Ok(&mut bound.inner)
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
    ///
    /// Output paths are checked for symlinks and their object identity is
    /// recorded. The eventual file descriptor is compared with that identity
    /// before any truncation or plaintext write; a replaced target fails
    /// closed instead of following the new path.
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

                let checked_target = check_output_path(file_path)?;

                return Ok(OutputWriter::File(LazyFile {
                    filename,
                    allow_overwrite,
                    checked_target,
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
