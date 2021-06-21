use crate::{
    keys::sodiumoxide::{
        SodiumOxidePublicAsymmetricKey, SodiumOxideSecretAsymmetricKey, SodiumOxideSymmetricKey,
        SodiumOxideSymmetricKeyBuilder, SodiumOxideSymmetricKeyUnsealable,
    },
    CryptoError, Storer,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Debug};

pub trait Buildable {
    type Builder: Builder<Output = Self>;

    fn builder() -> Self::Builder;
}

pub trait Builder: TryFrom<Builders, Error = CryptoError> {
    type Output;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError>;
}

#[async_trait]
pub trait Unsealer {
    async fn unseal<T: Storer>(&self, storer: T) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Builders {
    SodiumOxideSymmetricKey(SodiumOxideSymmetricKeyBuilder),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Unsealers {
    SodiumOxideSymmetricKey(SodiumOxideSymmetricKeyUnsealable),
}

#[async_trait]
impl Unsealer for Unsealers {
    async fn unseal<T: Storer>(&self, storer: T) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::SodiumOxideSymmetricKey(sosku) => sosku.unseal(storer).await,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    pub name: Name,
    pub value: States,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum States {
    Referenced {
        name: Name,
    },
    Sealed {
        builder: Builders,
        unsealable: Unsealers,
    },
    Unsealed {
        builder: Builders,
        bytes: Vec<u8>,
    },
}

pub type Name = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Types {
    Keys(KeyTypes),
    Data(DataTypes),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyTypes {
    Symmetric(SymmetricKeyTypes),
    Asymmetric(AsymmetricKeyTypes),
}

impl TryFrom<Types> for KeyTypes {
    type Error = CryptoError;

    fn try_from(value: Types) -> Result<Self, Self::Error> {
        match value {
            Types::Keys(kt) => Ok(kt),
            Types::Data(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SymmetricKeyTypes {
    SodiumOxide(SodiumOxideSymmetricKey),
}

impl TryFrom<Types> for SymmetricKeyTypes {
    type Error = CryptoError;

    fn try_from(value: Types) -> Result<Self, Self::Error> {
        let kt = KeyTypes::try_from(value)?;
        match kt {
            KeyTypes::Symmetric(skt) => Ok(skt),
            KeyTypes::Asymmetric(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AsymmetricKeyTypes {
    Public(PublicAsymmetricKeyTypes),
    Secret(SecretAsymmetricKeyTypes),
}

impl TryFrom<Types> for AsymmetricKeyTypes {
    type Error = CryptoError;

    fn try_from(value: Types) -> Result<Self, Self::Error> {
        let kt = KeyTypes::try_from(value)?;
        match kt {
            KeyTypes::Asymmetric(akt) => Ok(akt),
            KeyTypes::Symmetric(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PublicAsymmetricKeyTypes {
    SodiumOxide(SodiumOxidePublicAsymmetricKey),
}

impl TryFrom<Types> for PublicAsymmetricKeyTypes {
    type Error = CryptoError;

    fn try_from(value: Types) -> Result<Self, Self::Error> {
        let akt = AsymmetricKeyTypes::try_from(value)?;
        match akt {
            AsymmetricKeyTypes::Public(pakt) => Ok(pakt),
            AsymmetricKeyTypes::Secret(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecretAsymmetricKeyTypes {
    SodiumOxide(SodiumOxideSecretAsymmetricKey),
}

impl TryFrom<Types> for SecretAsymmetricKeyTypes {
    type Error = CryptoError;

    fn try_from(value: Types) -> Result<Self, Self::Error> {
        let akt = AsymmetricKeyTypes::try_from(value)?;
        match akt {
            AsymmetricKeyTypes::Secret(sakt) => Ok(sakt),
            AsymmetricKeyTypes::Public(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DataTypes {
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    String(String),
}
