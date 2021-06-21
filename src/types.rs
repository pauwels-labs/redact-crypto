use crate::{
    keys::sodiumoxide::{
        SodiumOxidePublicAsymmetricKey, SodiumOxideSecretAsymmetricKey, SodiumOxideSymmetricKey,
        SodiumOxideSymmetricKeyUnsealer,
    },
    AsymmetricKeyBuilder, CryptoError, DataBuilder, KeyBuilder, PublicAsymmetricKeyBuilder,
    SecretAsymmetricKeyBuilder, Storer, SymmetricKeyBuilder, TypeBuilder, TypeBuilderContainer,
};
use async_trait::async_trait;
use mongodb::bson::{self, Document};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Debug};

pub trait IntoIndex {
    fn into_index() -> Document;
}

pub trait Buildable {
    type Builder: Builder<Output = Self>;

    fn builder(&self) -> Self::Builder;
}

pub trait Builder: TryFrom<TypeBuilderContainer, Error = CryptoError> {
    type Output;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError>;
}

#[async_trait]
impl Unsealer for ByteUnsealer {
    async fn unseal<T: Storer>(&self, storer: T) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::SodiumOxideSymmetricKey(sosku) => sosku.unseal(storer).await,
        }
    }
}

#[async_trait]
pub trait Unsealer {
    async fn unseal<T: Storer>(&self, storer: T) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ByteUnsealer {
    SodiumOxideSymmetricKey(SodiumOxideSymmetricKeyUnsealer),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    pub path: EntryPath,
    pub value: States,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum States {
    Referenced {
        builder: TypeBuilder,
        path: EntryPath,
    },
    Sealed {
        builder: TypeBuilder,
        unsealer: ByteUnsealer,
    },
    Unsealed {
        builder: TypeBuilder,
        bytes: String,
    },
}

pub type EntryPath = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum Type {
    Key(Key),
    Data(Data),
}

impl IntoIndex for Type {
    fn into_index() -> Document {
        bson::doc! {}
    }
}

impl Buildable for Type {
    type Builder = TypeBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::Key(kb) => TypeBuilder::Key(kb.builder()),
            Self::Data(db) => TypeBuilder::Data(db.builder()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum Key {
    Symmetric(SymmetricKey),
    Asymmetric(AsymmetricKey),
}

impl IntoIndex for Key {
    fn into_index() -> Document {
        bson::doc! {
            "value": {
        "c": {
            "builder": {
        "t": "Key"
            }
        }
            }
        }
    }
}

impl Buildable for Key {
    type Builder = KeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::Symmetric(sk) => KeyBuilder::Symmetric(sk.builder()),
            Self::Asymmetric(ak) => KeyBuilder::Asymmetric(ak.builder()),
        }
    }
}

// impl TryFrom<Type> for Key {
//     type Error = CryptoError;

//     fn try_from(value: Type) -> Result<Self, Self::Error> {
//         match value {
//             Type::Key(kt) => Ok(kt),
//             Type::Data(_) => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum SymmetricKey {
    SodiumOxide(SodiumOxideSymmetricKey),
}

impl IntoIndex for SymmetricKey {
    fn into_index() -> Document {
        bson::doc! {
            "value": {
        "c": {
            "builder": {
        "t": "Key",
        "c": {
            "t": "Symmetric"
        }
            }
        }
            }
        }
    }
}

impl Buildable for SymmetricKey {
    type Builder = SymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::SodiumOxide(sosk) => SymmetricKeyBuilder::SodiumOxide(sosk.builder()),
        }
    }
}

// impl TryFrom<Type> for SymmetricKey {
//     type Error = CryptoError;

//     fn try_from(value: Type) -> Result<Self, Self::Error> {
//         let kt = Key::try_from(value)?;
//         match kt {
//             Key::Symmetric(skt) => Ok(skt),
//             Key::Asymmetric(_) => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum AsymmetricKey {
    Public(PublicAsymmetricKey),
    Secret(SecretAsymmetricKey),
}

impl IntoIndex for AsymmetricKey {
    fn into_index() -> Document {
        bson::doc! {
            "value": {
        "c": {
            "builder": {
        "t": "Key",
        "c": {
            "t": "Asymmetric",
        }
            }
        }
            }
        }
    }
}

impl Buildable for AsymmetricKey {
    type Builder = AsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::Public(pak) => AsymmetricKeyBuilder::Public(pak.builder()),
            Self::Secret(sak) => AsymmetricKeyBuilder::Secret(sak.builder()),
        }
    }
}

// impl TryFrom<Type> for AsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(value: Type) -> Result<Self, Self::Error> {
//         let kt = Key::try_from(value)?;
//         match kt {
//             Key::Asymmetric(akt) => Ok(akt),
//             Key::Symmetric(_) => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum PublicAsymmetricKey {
    SodiumOxide(SodiumOxidePublicAsymmetricKey),
}

impl IntoIndex for PublicAsymmetricKey {
    fn into_index() -> Document {
        bson::doc! {
            "value": {
        "c": {
            "builder": {
        "t": "Key",
        "c": {
            "t": "Asymmetric",
        "c": {
        "t": "Public"
        }
        }
            }
        }
            }
        }
    }
}

impl Buildable for PublicAsymmetricKey {
    type Builder = PublicAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::SodiumOxide(sopak) => PublicAsymmetricKeyBuilder::SodiumOxide(sopak.builder()),
        }
    }
}

// impl TryFrom<Type> for PublicAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(value: Type) -> Result<Self, Self::Error> {
//         let akt = AsymmetricKey::try_from(value)?;
//         match akt {
//             AsymmetricKey::Public(pakt) => Ok(pakt),
//             AsymmetricKey::Secret(_) => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum SecretAsymmetricKey {
    SodiumOxide(SodiumOxideSecretAsymmetricKey),
}

impl IntoIndex for SecretAsymmetricKey {
    fn into_index() -> Document {
        bson::doc! {
            "value": {
        "c": {
            "builder": {
        "t": "Key",
        "c": {
            "t": "Asymmetric",
        "c": {
        "t": "Secret"
        }
        }
            }
        }
            }
        }
    }
}

impl Buildable for SecretAsymmetricKey {
    type Builder = SecretAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::SodiumOxide(sosak) => SecretAsymmetricKeyBuilder::SodiumOxide(sosak.builder()),
        }
    }
}

// impl TryFrom<Type> for SecretAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(value: Type) -> Result<Self, Self::Error> {
//         let akt = AsymmetricKey::try_from(value)?;
//         match akt {
//             AsymmetricKey::Secret(sakt) => Ok(sakt),
//             AsymmetricKey::Public(_) => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct Data {
//     id: ID,
//     value: DataValue,
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum Data {
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    String(String),
}

impl IntoIndex for Data {
    fn into_index() -> Document {
        bson::doc! {
            "value": {
        "c": {
                    "builder": {
            "t": "Data",
            }
        }
            }
        }
    }
}

impl Buildable for Data {
    type Builder = DataBuilder;

    fn builder(&self) -> Self::Builder {
        DataBuilder {}
    }
}
