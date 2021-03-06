//! Sources provide some source material for creating a type. Currently, the only
//! implementations available are sources of bytes. A source provides an interface
//! for read/write operations on the set of bytes it covers.

use crate::CryptoError;
use base64::DecodeError;
use once_cell::sync::OnceCell;
use serde::{
    de::{self, Deserializer},
    Deserialize, Serialize, Serializer,
};
use std::{
    convert::Into,
    error::Error,
    fmt::{self, Display, Formatter},
    io::{self, ErrorKind},
    path::PathBuf as StdPathBuf,
    str::FromStr,
};

#[derive(Debug)]
pub enum NotFoundKind {
    File(String),
    Vector,
}

#[derive(Debug)]
pub enum SourceError {
    /// Error occurred while performing IO on the filesystem
    FsIoError { source: io::Error },

    /// Requested bytes were not found
    NotFound { kind: NotFoundKind },

    /// File path given has an invalid file name with no stem
    FilePathHasNoFileStem { path: String },

    /// File path given was invalid UTF-8
    FilePathIsInvalidUTF8,

    /// Error happened when decoding base64 string
    Base64Decode { source: DecodeError },
}

impl Error for SourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            SourceError::FsIoError { ref source } => Some(source),
            SourceError::NotFound { .. } => None,
            SourceError::FilePathHasNoFileStem { .. } => None,
            SourceError::FilePathIsInvalidUTF8 => None,
            SourceError::Base64Decode { ref source } => Some(source),
        }
    }
}

impl Display for SourceError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            SourceError::FsIoError { .. } => {
                write!(f, "Error occured during file system I/O")
            }
            SourceError::NotFound { ref kind } => match kind {
                NotFoundKind::File(path) => write!(f, "Path \"{}\" not found", path),
                NotFoundKind::Vector => write!(f, "Vector byte source contains no bytes"),
            },
            SourceError::FilePathHasNoFileStem { ref path } => {
                write!(
                    f,
                    "File path \"{}\" was invalid as the file name has no stem",
                    path
                )
            }
            SourceError::FilePathIsInvalidUTF8 => {
                write!(f, "Given file path was not valid UTF-8")
            }
            SourceError::Base64Decode { .. } => {
                write!(f, "Error occurred while decoding string from base64")
            }
        }
    }
}

impl From<SourceError> for CryptoError {
    fn from(mse: SourceError) -> Self {
        match mse {
            SourceError::NotFound { .. } => CryptoError::NotFound {
                source: Box::new(mse),
            },
            _ => CryptoError::InternalError {
                source: Box::new(mse),
            },
        }
    }
}

pub trait HasByteSource {
    fn byte_source(&self) -> ByteSource;
}

/// Enumerates all the different types of sources.
/// Currently supported:
/// - Bytes: sources that are represented as a byte array
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum Source {
    Byte(ByteSource),
}

/// Enumerates all the different types of byte-type sources.
/// Currently supported:
/// - Fs: data stored on the filesystem
/// - Vector: data stored in a vector of bytes
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum ByteSource {
    Fs(FsByteSource),
    Vector(VectorByteSource),
}

impl ByteSource {
    /// Sets the bytes of the source to the given value
    pub fn set(&mut self, key: &[u8]) -> Result<(), SourceError> {
        match self {
            ByteSource::Fs(fsbks) => fsbks.set(key),
            ByteSource::Vector(vbks) => vbks.set(key),
        }
    }

    /// Gets the bytes stored by the source
    pub fn get(&self) -> Result<&[u8], SourceError> {
        match self {
            ByteSource::Fs(fsbks) => fsbks.get(),
            ByteSource::Vector(vbks) => vbks.get(),
        }
    }
}

impl From<&[u8]> for ByteSource {
    fn from(value: &[u8]) -> Self {
        ByteSource::Vector(value.into())
    }
}

impl From<&str> for ByteSource {
    fn from(value: &str) -> Self {
        ByteSource::Vector(value.into())
    }
}

/// Represents a valid path
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Path {
    path: StdPathBuf,
    stem: String,
}

impl Path {
    pub fn file_stem(&self) -> &str {
        &self.stem
    }
}

impl<'a> From<&'a Path> for &'a StdPathBuf {
    fn from(path: &'a Path) -> Self {
        &path.path
    }
}

impl FromStr for Path {
    type Err = SourceError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let path: StdPathBuf = path.into();
        let stem = path
            .file_stem()
            .ok_or(SourceError::FilePathHasNoFileStem {
                path: path
                    .clone()
                    .into_os_string()
                    .into_string()
                    .unwrap_or_else(|_| "<Invalid UTF8>".to_owned()),
            })?
            .to_str()
            .ok_or(SourceError::FilePathIsInvalidUTF8)?
            .to_owned();

        Ok(Self { path, stem })
    }
}

/// A source that is a path to a file on the filesystem. The contents
/// of the file are cached on the first call to get(), and can be refreshed
/// by calling the reload() method.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FsByteSource {
    path: Path,
    #[serde(skip)]
    cached: OnceCell<VectorByteSource>,
}

impl FromStr for FsByteSource {
    type Err = SourceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = Path::from_str(s)?;
        Ok(FsByteSource::new(path))
    }
}

impl FsByteSource {
    /// Creates an `FsBytesSource` from a path on the filesystem
    pub fn new(path: Path) -> Self {
        let cached = OnceCell::new();
        FsByteSource { path, cached }
    }

    /// Reads a `VectorBytesSource` from a path on the filesystem
    fn read_from_path(path: &Path) -> Result<VectorByteSource, SourceError> {
        let path_ref: &StdPathBuf = path.into();
        let path_str = path
            .path
            .clone()
            .into_os_string()
            .into_string()
            .unwrap_or_else(|_| "<Invalid UTF8>".to_owned());

        // Mock this
        let read_bytes = std::fs::read(path_ref).map_err(|e| match e.kind() {
            ErrorKind::NotFound => SourceError::NotFound {
                kind: NotFoundKind::File(path_str),
            },
            _ => SourceError::FsIoError { source: e },
        })?;
        let bytes =
            base64::decode(read_bytes).map_err(|e| SourceError::Base64Decode { source: e })?;
        Ok(VectorByteSource { value: Some(bytes) })
    }

    /// Empties the cache, triggering a reload of the file on the next
    /// call to get. Note that this function does not perform any file
    /// I/O.
    pub fn reload(&mut self) {
        self.cached.take();
    }

    /// Re-writes the file at the path to the given bytes
    pub fn set(&mut self, value: &[u8]) -> Result<(), SourceError> {
        let path_ref: &StdPathBuf = (&self.path).into();
        let path_str = self
            .path
            .path
            .clone()
            .into_os_string()
            .into_string()
            .unwrap_or_else(|_| "<Invalid UTF8>".to_owned());
        let path_parent = path_ref.parent();
        let bytes = base64::encode(value);

        // If the path contains parent directories, try to create the chain of
        // directories first before making the file
        if let Some(path) = path_parent {
            std::fs::create_dir_all(path).map_err(|source| SourceError::FsIoError { source })?;
        }

        // Write the given bytes to the file at the given path
        std::fs::write(path_ref, bytes)
            .map(|_| self.reload())
            .map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => SourceError::NotFound {
                    kind: NotFoundKind::File(path_str),
                },
                _ => SourceError::FsIoError { source },
            })
    }

    /// Returns the bytes stored at the path
    pub fn get(&self) -> Result<&[u8], SourceError> {
        self.cached
            .get_or_try_init(|| Self::read_from_path(&self.path))?
            .get()
    }

    /// Returns the path where the key is stored
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A source that is an array of bytes in memory
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VectorByteSource {
    #[serde(
        serialize_with = "byte_vector_serialize",
        deserialize_with = "byte_vector_deserialize"
    )]
    value: Option<Vec<u8>>,
}

/// Custom serialization function base64-encodes the bytes before storage
fn byte_vector_serialize<S>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match bytes {
        Some(bytes) => {
            let b64_encoded = base64::encode(bytes);
            s.serialize_some(&Some(b64_encoded))
        }
        None => s.serialize_none(),
    }
}

/// Custom deserialization function base64-decodes the bytes before passing them back
fn byte_vector_deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let b64_encoded: Option<String> = de::Deserialize::deserialize(deserializer)?;
    match b64_encoded {
        Some(bytes) => Ok(Some(base64::decode(bytes).map_err(de::Error::custom)?)),
        None => Ok(None),
    }
}

impl VectorByteSource {
    /// Creates a new `VectorBytesSource` from the given byte array
    pub fn new(value: Option<&[u8]>) -> Self {
        match value {
            Some(value) => VectorByteSource {
                value: Some(value.to_vec()),
            },
            None => VectorByteSource { value: None },
        }
    }

    /// Re-writes the source to the given bytes
    pub fn set(&mut self, key: &[u8]) -> Result<(), SourceError> {
        self.value = Some(key.to_owned());
        Ok(())
    }

    /// Returns the stored bytes
    pub fn get(&self) -> Result<&[u8], SourceError> {
        match self.value {
            Some(ref bytes) => Ok(bytes.as_ref()),
            None => Err(SourceError::NotFound {
                kind: NotFoundKind::Vector,
            }),
        }
    }
}

impl From<&[u8]> for VectorByteSource {
    fn from(value: &[u8]) -> Self {
        Self::new(Some(value))
    }
}

impl From<&str> for VectorByteSource {
    fn from(value: &str) -> Self {
        Self::new(Some(value.as_ref()))
    }
}
