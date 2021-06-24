use crate::CryptoError;
use serde::{
    de::{self, Deserializer},
    Deserialize, Serialize, Serializer,
};
use std::{convert::Into, io::ErrorKind, path::PathBuf as StdPathBuf, str::FromStr};

/// Enumerates all the different types of sources.
/// Currently supported:
/// - Bytes: sources that can be deserialized to a byte array
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum Sources {
    Bytes(BytesSources),
}

/// Enumerates all the different types of byte-type sources.
/// Currently supported:
/// - Fs: data stored on the filesystem
/// - Vector: data stored in a vector of bytes
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum BytesSources {
    Fs(FsBytesSource),
    Vector(VectorBytesSource),
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
        let bytes =
            base64::decode(read_bytes).map_err(|e| CryptoError::Base64Decode { source: e })?;
        Ok(VectorBytesSource { value: bytes })
    }

    /// Re-reads the file and stores its bytes in memory
    pub fn reload(&mut self) -> Result<(), CryptoError> {
        self.cached = Some(Self::read_from_path(&self.path)?);
        Ok(())
    }

    /// Re-writes the key to be the given bytes
    pub fn set(&mut self, value: &[u8]) -> Result<(), CryptoError> {
        let path_ref: &StdPathBuf = (&self.path).into();
        let bytes = base64::encode(value);
        std::fs::write(path_ref, bytes)
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
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A source that is an array of bytes in memory
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VectorBytesSource {
    #[serde(
        serialize_with = "byte_vector_serialize",
        deserialize_with = "byte_vector_deserialize"
    )]
    value: Vec<u8>,
}

fn byte_vector_serialize<S>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = base64::encode(bytes);
    s.serialize_str(&bytes)
}

fn byte_vector_deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = de::Deserialize::deserialize(deserializer)?;
    base64::decode(s).map_err(de::Error::custom)
}

impl VectorBytesSource {
    /// Creates a new `VectorBytesSource` from the given byte array
    pub fn new(bytes: &[u8]) -> Self {
        VectorBytesSource {
            value: bytes.to_owned(),
        }
    }

    /// Re-writes the key to be the given bytes
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        self.value = key.to_owned();
        Ok(())
        // self.value = Some(key.to_vec());
        // Ok(())
    }

    /// Returns the key as an array of bytes
    pub fn get(&self) -> Result<&[u8], CryptoError> {
        Ok(self.value.as_ref())
        // match self.value {
        //     Some(ref v) => Ok(&v),
        //     None => Err(CryptoError::NotFound),
        // }
    }
}
