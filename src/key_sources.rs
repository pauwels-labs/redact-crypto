use crate::error::CryptoError;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValueKeySource {
    value: Vec<u8>,
}

impl ValueKeySource {
    pub fn bytes(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FsKeySource {
    path: String,
}

impl TryFrom<FsKeySource> for ValueKeySource {
    type Error = CryptoError;

    fn try_from(ks: FsKeySource) -> Result<Self, Self::Error> {
        Ok(ValueKeySource {
            value: std::fs::read(ks.path).map_err(|e| CryptoError::FsIoError { source: e })?,
        })
    }
}

impl TryFrom<KeySources> for ValueKeySource {
    type Error = CryptoError;

    fn try_from(ks: KeySources) -> Result<Self, Self::Error> {
        match ks {
            KeySources::Value(vks) => Ok(vks),
            KeySources::Fs(fsks) => fsks.try_into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeySources {
    Value(ValueKeySource),
    Fs(FsKeySource),
}
