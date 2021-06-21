use crate::{
    keys::sodiumoxide::{
        SodiumOxidePublicAsymmetricKey, SodiumOxideSecretAsymmetricKey, SodiumOxideSymmetricKey,
        SodiumOxideSymmetricKeyUnsealer,
    },
    AsymmetricKeyBuilder, CryptoError, KeyBuilder, PublicAsymmetricKeyBuilder,
    SecretAsymmetricKeyBuilder, Storer, SymmetricKeyBuilder, TypeBuilder,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Debug};

pub trait Buildable {
    type Builder: Builder<Output = Self>;

    fn builder(&self) -> Self::Builder;
}

pub trait Builder: TryFrom<TypeBuilder, Error = CryptoError> {
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
    pub name: Name,
    pub value: States,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum States {
    Referenced {
        name: Name,
    },
    Sealed {
        builder: TypeBuilder,
        unsealer: ByteUnsealer,
    },
    Unsealed {
        builder: TypeBuilder,
        bytes: Vec<u8>,
    },
}

pub type Name = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Type {
    Key(Key),
    Data(Data),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Key {
    Symmetric(SymmetricKey),
    Asymmetric(AsymmetricKey),
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
pub enum SymmetricKey {
    SodiumOxide(SodiumOxideSymmetricKey),
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
pub enum AsymmetricKey {
    Public(PublicAsymmetricKey),
    Secret(SecretAsymmetricKey),
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
pub enum PublicAsymmetricKey {
    SodiumOxide(SodiumOxidePublicAsymmetricKey),
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
pub enum SecretAsymmetricKey {
    SodiumOxide(SodiumOxideSecretAsymmetricKey),
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Data {
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    String(String),
}

impl Buildable for Data {
    type Builder = DataBuilder;

    fn builder(&self) -> Self::Builder {
        DataBuilder {}
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct DataBuilder {}

impl TryFrom<TypeBuilder> for DataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
            TypeBuilder::Data(db) => Ok(db),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for DataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        if let Ok(b) = serde_json::from_slice::<bool>(bytes) {
            Ok(Data::Bool(b))
        } else if let Ok(u) = serde_json::from_slice::<u64>(bytes) {
            Ok(Data::U64(u))
        } else if let Ok(i) = serde_json::from_slice::<i64>(bytes) {
            Ok(Data::I64(i))
        } else if let Ok(f) = serde_json::from_slice::<f64>(bytes) {
            Ok(Data::F64(f))
        } else if let Ok(s) = serde_json::from_slice::<String>(bytes) {
            Ok(Data::String(s))
        } else {
            Err(CryptoError::NotDeserializableToBaseDataType)
        }
    }
}
