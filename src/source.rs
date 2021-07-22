//! Sources provide some source material for creating a type. Currently, the only
//! implementations available are sources of bytes. A source provides an interface
//! for read/write operations on the set of bytes it covers.

use crate::CryptoError;
use once_cell::sync::OnceCell;
use serde::{
    de::{self, Deserializer},
    Deserialize, Serialize, Serializer,
};
use std::{convert::Into, io::ErrorKind, path::PathBuf as StdPathBuf, str::FromStr};

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
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        match self {
            ByteSource::Fs(fsbks) => fsbks.set(key),
            ByteSource::Vector(vbks) => vbks.set(key),
        }
    }

    /// Gets the bytes stored by the source
    pub fn get(&self) -> Result<&[u8], CryptoError> {
        match self {
            ByteSource::Fs(fsbks) => fsbks.get(),
            ByteSource::Vector(vbks) => vbks.get(),
        }
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
    type Err = CryptoError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let path: StdPathBuf = path.into();
        let stem = path
            .file_stem()
            .ok_or(CryptoError::FilePathHasNoFileStem {
                path: path
                    .clone()
                    .into_os_string()
                    .into_string()
                    .unwrap_or_else(|_| "<Invalid UTF8>".to_owned()),
            })?
            .to_str()
            .ok_or(CryptoError::FilePathIsInvalidUTF8)?
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
    type Err = CryptoError;

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
    fn read_from_path(path: &Path) -> Result<VectorByteSource, CryptoError> {
        let path_ref: &StdPathBuf = path.into();
        let path_str = path
            .path
            .clone()
            .into_os_string()
            .into_string()
            .unwrap_or_else(|_| "<Invalid UTF8>".to_owned());

        // Mock this
        let read_bytes = std::fs::read(path_ref).map_err(|e| match e.kind() {
            ErrorKind::NotFound => CryptoError::FileNotFound { path: path_str },
            _ => CryptoError::FsIoError { source: e },
        })?;
        let bytes =
            base64::decode(read_bytes).map_err(|e| CryptoError::Base64Decode { source: e })?;
        Ok(VectorByteSource { value: bytes })
    }

    /// Empties the cache, triggering a reload of the file on the next
    /// call to get. Note that this function does not perform any file
    /// I/O.
    pub fn reload(&mut self) {
        self.cached.take();
    }

    /// Re-writes the file at the path to the given bytes
    pub fn set(&mut self, value: &[u8]) -> Result<(), CryptoError> {
        let path_ref: &StdPathBuf = (&self.path).into();
        let path_str = self
            .path
            .path
            .clone()
            .into_os_string()
            .into_string()
            .unwrap_or_else(|_| "<Invalid UTF8>".to_owned());

        let bytes = base64::encode(value);
        std::fs::write(path_ref, bytes)
            .map(|_| self.reload())
            .map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => CryptoError::FileNotFound { path: path_str },
                _ => CryptoError::FsIoError { source },
            })
    }

    /// Returns the bytes stored at the path
    pub fn get(&self) -> Result<&[u8], CryptoError> {
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
    value: Vec<u8>,
}

/// Custom serialization function base64-encodes the bytes before storage
fn byte_vector_serialize<S>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = base64::encode(bytes);
    s.serialize_str(&bytes)
}

/// Custom deserialization function base64-decodes the bytes before passing them back
fn byte_vector_deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = de::Deserialize::deserialize(deserializer)?;
    base64::decode(s).map_err(de::Error::custom)
}

impl VectorByteSource {
    /// Creates a new `VectorBytesSource` from the given byte array
    pub fn new(bytes: &[u8]) -> Self {
        VectorByteSource {
            value: bytes.to_owned(),
        }
    }

    /// Re-writes the source to the given bytes
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        self.value = key.to_owned();
        Ok(())
    }

    /// Returns the stored bytes
    pub fn get(&self) -> Result<&[u8], CryptoError> {
        Ok(self.value.as_ref())
    }
}
