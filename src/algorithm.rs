use crate::{
    key::sodiumoxide::{
        SodiumOxidePublicAsymmetricKeyAlgorithm, SodiumOxideSecretAsymmetricKeyAlgorithm,
        SodiumOxideSymmetricKeyAlgorithm,
    },
    ByteSource, CryptoError,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[async_trait]
pub trait Algorithm {
    type Source;
    type Output;

    async fn unseal(&self, source: &Self::Source) -> Result<Self::Output, CryptoError>;
    async fn seal(&self, source: &Self::Source) -> Result<Self::Output, CryptoError>;
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", content = "c")]
pub enum ByteAlgorithm {
    SodiumOxideSymmetricKey(SodiumOxideSymmetricKeyAlgorithm),
    SodiumOxideSecretAsymmetricKey(SodiumOxideSecretAsymmetricKeyAlgorithm),
    SodiumOxidePublicAsymmetricKey(SodiumOxidePublicAsymmetricKeyAlgorithm),
}

#[async_trait]
impl Algorithm for ByteAlgorithm {
    type Source = ByteSource;
    type Output = ByteSource;

    async fn unseal(&self, source: &Self::Source) -> Result<Self::Output, CryptoError> {
        match self {
            Self::SodiumOxideSymmetricKey(sosku) => sosku.unseal(source).await,
            Self::SodiumOxideSecretAsymmetricKey(sosaku) => sosaku.unseal(source).await,
            Self::SodiumOxidePublicAsymmetricKey(sopaku) => sopaku.unseal(source).await,
        }
    }

    async fn seal(&self, source: &Self::Source) -> Result<Self::Output, CryptoError> {
        match self {
            Self::SodiumOxideSymmetricKey(sosku) => sosku.seal(source).await,
            Self::SodiumOxideSecretAsymmetricKey(sosaku) => sosaku.seal(source).await,
            Self::SodiumOxidePublicAsymmetricKey(sopaku) => sopaku.seal(source).await,
        }
    }
}

// impl ByteAlgorithm {
//     pub fn get_source(&self) -> &ByteSource {
//         match self {
//             Self::SodiumOxideSymmetricKey(sosku) => &sosku.source,
//             Self::SodiumOxideSecretAsymmetricKey(sosaku) => &sosaku.source,
//             Self::SodiumOxidePublicAsymmetricKey(sopaku) => &sopaku.source,
//         }
//     }
// }
