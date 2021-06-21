use crate::{CryptoError, Name};
use serde::{Deserialize, Serialize};
use std::{convert::Into, io::ErrorKind, path::PathBuf as StdPathBuf, str::FromStr};

/// Enumerates all the different types of sources.
/// Currently supported:
/// - Bytes: sources that can be deserialized to a byte array
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Sources {
    Bytes(BytesSources),
}

/// Enumerates all the different types of byte-type sources.
/// Currently supported:
/// - Fs: data stored on the filesystem
/// - Vector: data stored in a vector of bytes
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BytesSources {
    Fs(FsBytesSource),
    Vector(VectorBytesSource),
}

impl BytesSources {
    pub fn name(&self) -> Name {
        match self {
            Self::Fs(fsbs) => fsbs.name(),
            Self::Vector(vbs) => vbs.name(),
        }
    }
}

impl BytesSources {
    /// Sets the bytes of the key to the given value
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        match self {
            BytesSources::Fs(fsbks) => fsbks.set(key),
            BytesSources::Vector(vbks) => vbks.set(key),
        }
    }

    /// Gets the byte array of the key
    pub fn get(&self) -> Result<&[u8], CryptoError> {
        match self {
            BytesSources::Fs(fsbks) => fsbks.get(),
            BytesSources::Vector(vbks) => vbks.get(),
        }
    }
}

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
            .ok_or(CryptoError::FilePathHasNoFileStem)?
            .to_str()
            .ok_or(CryptoError::FilePathIsInvalidUTF8)?
            .to_owned();

        Ok(Self { path, stem })
    }
}

/// A source that is a path to a file on the filesystem
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FsBytesSource {
    path: Path,
    #[serde(skip)]
    cached: Option<VectorBytesSource>,
}

impl FsBytesSource {
    /// Creates an `FsBytesSource` from a path on the filesystem
    pub fn new(path: &str) -> Result<Self, CryptoError> {
        let path = Path::from_str(path)?;
        match Self::read_from_path(&path) {
            Ok(vbks) => Ok(Self {
                path,
                cached: Some(vbks),
            }),
            Err(e) => Err(e),
        }
    }

    /// Reads a `VectorBytesSource` from a path on the filesystem
    fn read_from_path(path: &Path) -> Result<VectorBytesSource, CryptoError> {
        let path_ref: &StdPathBuf = path.into();

        // Mock this
        let read_bytes = std::fs::read(path_ref).map_err(|e| match e.kind() {
            ErrorKind::NotFound => CryptoError::NotFound,
            _ => CryptoError::FsIoError { source: e },
        })?;
        Ok(VectorBytesSource {
            name: path.file_stem().into(),
            value: Some(read_bytes),
        })
    }

    /// Re-reads the file and stores its bytes in memory
    pub fn reload(&mut self) -> Result<(), CryptoError> {
        self.cached = Some(Self::read_from_path(&self.path)?);
        Ok(())
    }

    /// Re-writes the key to be the given bytes
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        let path_ref: &StdPathBuf = (&self.path).into();
        std::fs::write(path_ref, key)
            .map(|_| self.reload())
            .map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => CryptoError::NotFound,
                _ => CryptoError::FsIoError { source },
            })?
    }

    /// Returns the key as a byte array
    pub fn get(&self) -> Result<&[u8], CryptoError> {
        match self.cached {
            Some(ref vbks) => vbks.get(),
            None => Err(CryptoError::NotFound),
        }
    }

    /// Returns the path where the key is stored
    pub fn get_path(&self) -> &Path {
        &self.path
    }

    pub fn name(&self) -> Name {
        self.path.file_stem().to_owned()
    }
}

/// A source that is an array of bytes in memory
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VectorBytesSource {
    name: Name,
    value: Option<Vec<u8>>,
}

impl VectorBytesSource {
    /// Creates a new `VectorBytesSource` from the given byte array
    pub fn new(name: Name, bytes: Option<&[u8]>) -> Self {
        VectorBytesSource {
            name,
            value: bytes.map(|bytes| bytes.to_vec()),
        }
    }

    /// Re-writes the key to be the given bytes
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        self.value = Some(key.to_vec());
        Ok(())
    }

    /// Returns the key as an array of bytes
    pub fn get(&self) -> Result<&[u8], CryptoError> {
        match self.value {
            Some(ref v) => Ok(&v),
            None => Err(CryptoError::NotFound),
        }
    }

    pub fn name(&self) -> Name {
        self.name.clone()
    }
}
