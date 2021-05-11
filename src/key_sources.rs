use crate::error::CryptoError;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

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

    pub fn get(&mut self) -> Result<&[u8], CryptoError> {
        match self {
            BytesKeySources::Fs(fsbks) => fsbks.get(),
            BytesKeySources::Vector(vbks) => vbks.get(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FsBytesKeySource {
    path: String,
    #[serde(skip)]
    cached: Option<VectorBytesKeySource>,
}

impl FsBytesKeySource {
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        std::fs::write(&self.path, key)
            .map(|_| {
                self.cached = Some(VectorBytesKeySource {
                    value: Some(key.to_vec()),
                });
            })
            .map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => CryptoError::NotFound,
                _ => CryptoError::FsIoError { source },
            })
    }

    pub fn get(&mut self) -> Result<&[u8], CryptoError> {
        match self.cached {
            Some(ref mut vbks) => vbks.get(),
            None => {
                let read_bytes =
                    std::fs::read(&self.path).map_err(|e| CryptoError::FsIoError { source: e })?;
                let vbks = VectorBytesKeySource {
                    value: Some(read_bytes),
                };
                self.cached = Some(vbks);
                self.get()
            }
        }
    }
}

impl VectorBytesKeySource {
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        self.value = Some(key.to_vec());
        Ok(())
    }

    pub fn get(&mut self) -> Result<&[u8], CryptoError> {
        match self.value {
            Some(ref v) => Ok(&v),
            None => Err(CryptoError::NotFound),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VectorBytesKeySource {
    pub value: Option<Vec<u8>>,
}

impl TryFrom<KeySources> for BytesKeySources {
    type Error = CryptoError;

    fn try_from(ks: KeySources) -> Result<Self, Self::Error> {
        match ks {
            KeySources::Bytes(bks) => Ok(bks),
        }
    }
}
