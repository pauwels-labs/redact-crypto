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

// impl KeySources {
//     pub fn set(&self, key: &[u8]) -> Result<(), CryptoError> {
//         match self {
//             KeySources::Bytes(bks) => bks.set(key),
//         }
//     }
// }

// impl BytesKeySources {
//     pub fn set(&self, key: &[u8]) -> Result<(), CryptoError> {
//         match self {
//             BytesKeySources::Fs(fsbks) => fsbks.set(key),
//             BytesKeySources::Vector(vbks) => vbks.set(key),
//         }
//     }

//     pub fn try_bytes(&self) -> Result<Vec<u8>, CryptoError> {
//         match self {
//             BytesKeySources::Fs(fsbks) => match fsbks.cached.read().unwrap().0 {
//                 Some(ref vbks) => Ok(vbks.value.clone()),
//                 None => {
//                     let read_bytes = std::fs::read(&fsbks.path)
//                         .map_err(|e| CryptoError::FsIoError { source: e })?;
//                     let vbks = VectorBytesKeySource { value: read_bytes };
//                     fsbks.cached.write().unwrap().0 = Some(vbks);
//                     self.try_bytes()
//                 }
//             },
//             BytesKeySources::Vector(vbks) => Ok(vbks.value.clone()),
//         }
//     }
// }
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
                    value: key.to_vec(),
                });
            })
            .map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => CryptoError::NotFound,
                _ => CryptoError::FsIoError { source },
            })
    }

    pub fn get(&mut self) -> Result<&[u8], CryptoError> {
        match self.cached {
            Some(ref vbks) => Ok(&vbks.value),
            None => {
                let read_bytes =
                    std::fs::read(&self.path).map_err(|e| CryptoError::FsIoError { source: e })?;
                let vbks = VectorBytesKeySource { value: read_bytes };
                self.cached = Some(vbks);
                self.get()
            }
        }
    }
}

impl VectorBytesKeySource {
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        self.value = key.to_vec();
        Ok(())
    }

    pub fn get(&mut self) -> Result<&[u8], CryptoError> {
        Ok(&self.value)
    }
}

// #[derive(Default, Debug, Clone)]
// pub struct OptionVectorBytesKeySource(Option<VectorBytesKeySource>);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VectorBytesKeySource {
    pub value: Vec<u8>,
}

impl TryFrom<KeySources> for BytesKeySources {
    type Error = CryptoError;

    fn try_from(ks: KeySources) -> Result<Self, Self::Error> {
        match ks {
            KeySources::Bytes(bks) => Ok(bks),
        }
    }
}

// pub enum FsKeySource {
//     Read { path: String, vks: ValueKeySource },
//     Unread { path: String },
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct FsKeySource {
//     pub path: String,
//     pub vks: Option<ValueKeySource>,
// }

// impl TryFrom<FsKeySource> for ValueKeySource {
//     type Error = CryptoError;

//     fn try_from(mut ks: FsKeySource) -> Result<Self, Self::Error> {
//         if let Some(vks) = ks.vks {
//             Ok(vks)
//         } else {
//             let vks = ValueKeySource {
//                 value: std::fs::read(ks.path).map_err(|e| CryptoError::FsIoError { source: e })?,
//             };
//             ks.vks = Some(vks.clone());
//             Ok(vks)
//         }
//     }
// }

// impl TryFrom<KeySources> for ValueKeySource {
//     type Error = CryptoError;

//     fn try_from(ks: KeySources) -> Result<Self, Self::Error> {
//         match ks {
//             KeySources::Value(vks) => Ok(vks),
//             KeySources::Fs(fsks) => fsks.try_into(),
//         }
//     }
// }
