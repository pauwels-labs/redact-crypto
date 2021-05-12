use crate::error::CryptoError;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, io::ErrorKind};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeySources {
    Bytes(BytesKeySources),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BytesKeySources {
    Fs(FsBytesKeySource),
    Vector(VectorBytesKeySource),
}

impl BytesKeySources {
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        match self {
            BytesKeySources::Fs(fsbks) => fsbks.set(key),
            BytesKeySources::Vector(vbks) => vbks.set(key),
        }
    }

    pub fn get(&self) -> Result<&[u8], CryptoError> {
        match self {
            BytesKeySources::Fs(fsbks) => fsbks.get(),
            BytesKeySources::Vector(vbks) => vbks.get(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FsUncachedBytesKeySource {
    path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(try_from = "FsUncachedBytesKeySource")]
#[serde(into = "FsUncachedBytesKeySource")]
pub struct FsBytesKeySource {
    path: String,
    #[serde(skip)]
    cached: Option<VectorBytesKeySource>,
}

impl TryFrom<FsUncachedBytesKeySource> for FsBytesKeySource {
    type Error = CryptoError;

    fn try_from(fsubks: FsUncachedBytesKeySource) -> Result<Self, Self::Error> {
        FsBytesKeySource::new(&fsubks.path)
    }
}

impl From<FsBytesKeySource> for FsUncachedBytesKeySource {
    fn from(fsbks: FsBytesKeySource) -> Self {
        FsUncachedBytesKeySource {
            path: fsbks.get_path().to_owned(),
        }
    }
}

impl FsBytesKeySource {
    // Associated methods
    pub fn new(path: &str) -> Result<Self, CryptoError> {
        let vbks = Self::read_from_path(path)?;
        Ok(Self {
            path: path.to_owned(),
            cached: Some(vbks),
        })
    }

    fn read_from_path(path: &str) -> Result<VectorBytesKeySource, CryptoError> {
        // Mock this
        let read_bytes = std::fs::read(path).map_err(|e| match e.kind() {
            ErrorKind::NotFound => CryptoError::NotFound,
            _ => CryptoError::FsIoError { source: e },
        })?;
        Ok(VectorBytesKeySource {
            value: Some(read_bytes),
        })
    }

    // Self methods
    pub fn reload(&mut self) -> Result<(), CryptoError> {
        self.cached = Some(Self::read_from_path(&self.path)?);
        Ok(())
    }

    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        std::fs::write(&self.path, key)
            .map(|_| self.reload())
            .map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => CryptoError::NotFound,
                _ => CryptoError::FsIoError { source },
            })?
    }

    pub fn get(&self) -> Result<&[u8], CryptoError> {
        match self.cached {
            Some(ref vbks) => vbks.get(),
            None => Err(CryptoError::NotFound),
        }
    }

    pub fn get_path(&self) -> &str {
        &self.path
    }
}

impl VectorBytesKeySource {
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        self.value = Some(key.to_vec());
        Ok(())
    }

    pub fn get(&self) -> Result<&[u8], CryptoError> {
        match self.value {
            Some(ref v) => Ok(&v),
            None => Err(CryptoError::NotFound),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VectorBytesKeySource {
    value: Option<Vec<u8>>,
}

impl VectorBytesKeySource {
    pub fn new(bytes: &[u8]) -> Self {
        VectorBytesKeySource {
            value: Some(bytes.to_vec()),
        }
    }
}

impl TryFrom<KeySources> for BytesKeySources {
    type Error = CryptoError;

    fn try_from(ks: KeySources) -> Result<Self, Self::Error> {
        match ks {
            KeySources::Bytes(bks) => Ok(bks),
        }
    }
}

impl TryFrom<&KeySources> for BytesKeySources {
    type Error = CryptoError;

    fn try_from(ks: &KeySources) -> Result<Self, Self::Error> {
        match ks {
            KeySources::Bytes(bks) => match bks {
                BytesKeySources::Fs(fsbks) => Ok(BytesKeySources::Fs(fsbks.clone())),
                BytesKeySources::Vector(vbks) => Ok(BytesKeySources::Vector(vbks.clone())),
            },
        }
    }
}
