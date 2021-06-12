use crate::{
    keys::sodiumoxide::{
        SealedSodiumOxidePublicAsymmetricKey, SealedSodiumOxideSecretAsymmetricKey,
        SealedSodiumOxideSymmetricKey,
    },
    CryptoError,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_type")]
pub enum SealedTypes {
    Keys(SealedKeyTypes),
    Data(SealedDataTypes),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_key_type")]
pub enum SealedKeyTypes {
    Symmetric(SealedSymmetricKeyTypes),
    Asymmetric(SealedAsymmetricKeyTypes),
}

impl TryFrom<SealedTypes> for SealedKeyTypes {
    type Error = CryptoError;

    fn try_from(value: SealedTypes) -> Result<Self, Self::Error> {
        match value {
            SealedTypes::Keys(skt) => Ok(skt),
            SealedTypes::Data(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_symmetric_key_type")]
pub enum SealedSymmetricKeyTypes {
    SodiumOxide(SealedSodiumOxideSymmetricKey),
}

impl TryFrom<SealedTypes> for SealedSymmetricKeyTypes {
    type Error = CryptoError;

    fn try_from(value: SealedTypes) -> Result<Self, Self::Error> {
        let skt: SealedKeyTypes = SealedKeyTypes::try_from(value)?;
        match skt {
            SealedKeyTypes::Symmetric(sskt) => Ok(sskt),
            SealedKeyTypes::Asymmetric(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_asymmetric_key_type")]
pub enum SealedAsymmetricKeyTypes {
    Public(SealedPublicAsymmetricKeyTypes),
    Secret(SealedSecretAsymmetricKeyTypes),
}

impl TryFrom<SealedTypes> for SealedAsymmetricKeyTypes {
    type Error = CryptoError;

    fn try_from(value: SealedTypes) -> Result<Self, Self::Error> {
        let skt: SealedKeyTypes = SealedKeyTypes::try_from(value)?;
        match skt {
            SealedKeyTypes::Asymmetric(sakt) => Ok(sakt),
            SealedKeyTypes::Symmetric(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_public_asymmetric_key_type")]
pub enum SealedPublicAsymmetricKeyTypes {
    SodiumOxide(SealedSodiumOxidePublicAsymmetricKey),
}

impl TryFrom<SealedTypes> for SealedPublicAsymmetricKeyTypes {
    type Error = CryptoError;

    fn try_from(value: SealedTypes) -> Result<Self, Self::Error> {
        let sakt: SealedAsymmetricKeyTypes = SealedAsymmetricKeyTypes::try_from(value)?;
        match sakt {
            SealedAsymmetricKeyTypes::Public(spakt) => Ok(spakt),
            SealedAsymmetricKeyTypes::Secret(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_secret_asymmetric_key_type")]
pub enum SealedSecretAsymmetricKeyTypes {
    SodiumOxide(SealedSodiumOxideSecretAsymmetricKey),
}

impl TryFrom<SealedTypes> for SealedSecretAsymmetricKeyTypes {
    type Error = CryptoError;

    fn try_from(value: SealedTypes) -> Result<Self, Self::Error> {
        let sakt: SealedAsymmetricKeyTypes = SealedAsymmetricKeyTypes::try_from(value)?;
        match sakt {
            SealedAsymmetricKeyTypes::Secret(spakt) => Ok(spakt),
            SealedAsymmetricKeyTypes::Public(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SealedDataTypes {
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    String(String),
}
