use std::io::ErrorKind;

use crate::CryptoError;
use serde::{Deserialize, Serialize};

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct MaybeSealedSourceCollection<T>(pub Vec<MaybeSealedSource<T>>);

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct SealedSource {
//     pub source: Sources,
//     pub decryptedby: UnsealKeyRefs,
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// #[serde(tag = "seal_status")]
// pub enum MaybeSealedSource<T> {
//     Sealed(SealedSource),
//     Unsealed(T),
// }

// impl<T> MaybeSealedSource<T> {
//     pub async fn unseal(&self, store: impl KeyStorer) -> Result<&T, CryptoError> {
//         match self {
//             Self::Sealed(ss) => match ss.decryptedby {
//                 UnsealKeyRefs::Symmetric(sdkr) => {
//                     let sealed_decryption_key = sdkr.get(store).await?;
//                     let decryption_key = sealed_decryption_key.unseal(store).await?;
//                     let source = decryption_key.try_unseal(ss.source, sdkr.nonce)?;
//                 }
//                 UnsealKeyRefs::Asymmetric(adkr) => {
//                     let decryption_key = adkr.get(store).await?;
//                 }
//             },
//             Self::Unsealed(uk) => Ok(uk),
//         }
//     }
// }

/// Enumerates all the different types of sources.
/// Currently supported:
/// - Bytes: sources that can be deserialized to a byte array
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "source_type")]
pub enum Sources {
    Bytes(BytesSources),
}

/// Enumerates all the different types of byte-type sources.
/// Currently supported:
/// - Fs: data stored on the filesystem
/// - Vector: data stored in a vector of bytes
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "bytes_source_type")]
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

/// A source that is a path to a file on the filesystem
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FsBytesSource {
    path: String,
    #[serde(skip)]
    cached: Option<VectorBytesSource>,
}

impl FsBytesSource {
    /// Creates an `FsBytesSource` from a path on the filesystem
    pub fn new(path: &str) -> Result<Self, CryptoError> {
        match Self::read_from_path(path) {
            Ok(vbks) => Ok(Self {
                path: path.to_owned(),
                cached: Some(vbks),
            }),
            Err(e) => match e {
                CryptoError::NotFound => Ok(Self {
                    path: path.to_owned(),
                    cached: None,
                }),
                _ => Err(e),
            },
        }
    }

    /// Reads a `VectorBytesSource` from a path on the filesystem
    fn read_from_path(path: &str) -> Result<VectorBytesSource, CryptoError> {
        // Mock this
        let read_bytes = std::fs::read(path).map_err(|e| match e.kind() {
            ErrorKind::NotFound => CryptoError::NotFound,
            _ => CryptoError::FsIoError { source: e },
        })?;
        Ok(VectorBytesSource {
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
        std::fs::write(&self.path, key)
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
    pub fn get_path(&self) -> &str {
        &self.path
    }
}

/// A source that is an array of bytes in memory
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VectorBytesSource {
    value: Option<Vec<u8>>,
}

impl VectorBytesSource {
    /// Creates a new `VectorBytesSource` from the given byte array
    pub fn new(bytes: Option<&[u8]>) -> Self {
        VectorBytesSource {
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
}
