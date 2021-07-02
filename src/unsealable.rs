use crate::{
    key::sodiumoxide::SodiumOxideSymmetricKeyUnsealable, ByteSealable, ByteSource, CryptoError,
    Storer,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait Unsealable {
    async fn unseal<S: Storer>(self, storer: S) -> Result<ByteSealable, CryptoError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum ByteUnsealable {
    SodiumOxideSymmetricKey(SodiumOxideSymmetricKeyUnsealable),
}

#[async_trait]
impl Unsealable for ByteUnsealable {
    async fn unseal<S: Storer>(self, storer: S) -> Result<ByteSealable, CryptoError> {
        match self {
            Self::SodiumOxideSymmetricKey(sosku) => sosku.unseal(storer).await,
        }
    }
}

impl ByteUnsealable {
    pub fn get_source(&self) -> &ByteSource {
        match self {
            Self::SodiumOxideSymmetricKey(sosku) => &sosku.source,
        }
    }
}
