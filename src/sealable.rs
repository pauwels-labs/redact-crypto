use crate::{
    key::sodiumoxide::{
        SodiumOxidePublicAsymmetricKeySealable, SodiumOxideSecretAsymmetricKeySealable,
        SodiumOxideSymmetricKeySealable,
    },
    ByteSource, ByteUnsealable, CryptoError, Storer,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait Sealable {
    async fn seal<S: Storer>(self, storer: S) -> Result<ByteUnsealable, CryptoError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum ByteSealable {
    SodiumOxideSymmetricKey(SodiumOxideSymmetricKeySealable),
    SodiumOxideSecretAsymmetricKey(SodiumOxideSecretAsymmetricKeySealable),
    SodiumOxidePublicAsymmetricKey(SodiumOxidePublicAsymmetricKeySealable),
}

#[async_trait]
impl Sealable for ByteSealable {
    async fn seal<S: Storer>(self, storer: S) -> Result<ByteUnsealable, CryptoError> {
        match self {
            Self::SodiumOxideSymmetricKey(sosks) => sosks.seal(storer).await,
            Self::SodiumOxideSecretAsymmetricKey(sosaks) => sosaks.seal(storer).await,
            Self::SodiumOxidePublicAsymmetricKey(sopaks) => sopaks.seal(storer).await,
        }
    }
}

impl ByteSealable {
    pub fn get_source(&self) -> &ByteSource {
        match self {
            Self::SodiumOxideSymmetricKey(sosks) => &sosks.source,
            Self::SodiumOxideSecretAsymmetricKey(sosaks) => &sosaks.source,
            Self::SodiumOxidePublicAsymmetricKey(sopaks) => &sopaks.source,
        }
    }
}
