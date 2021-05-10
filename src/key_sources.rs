use crate::error::CryptoError;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValueKeySource {
    pub value: Vec<u8>,
}

impl ValueKeySource {
    pub fn bytes(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FsKeySource {
    pub path: String,
    pub vks: Option<ValueKeySource>,
}

impl TryFrom<FsKeySource> for ValueKeySource {
    type Error = CryptoError;

    fn try_from(mut ks: FsKeySource) -> Result<Self, Self::Error> {
        if let Some(vks) = ks.vks {
            Ok(vks)
        } else {
            let vks = ValueKeySource {
                value: std::fs::read(ks.path).map_err(|e| CryptoError::FsIoError { source: e })?,
            };
            ks.vks = Some(vks.clone());
            Ok(vks)
        }
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
