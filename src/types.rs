use crate::{
    keys::sodiumoxide::{
        SodiumOxidePublicAsymmetricKey, SodiumOxideSecretAsymmetricKey, SodiumOxideSymmetricKey,
        SodiumOxideSymmetricKeySealable, SodiumOxideSymmetricKeyUnsealable,
    },
    AsymmetricKeyBuilder, BytesSources, CryptoError, DataBuilder, KeyBuilder,
    PublicAsymmetricKeyBuilder, SecretAsymmetricKeyBuilder, Storer, SymmetricKeyBuilder,
    TypeBuilder, TypeBuilderContainer, VectorBytesSource,
};
use async_trait::async_trait;
use mongodb::bson::{self, Document};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fmt::{Debug, Display},
};

pub trait IntoIndex {
    fn into_index() -> Option<Document>;
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
pub trait Sealable {
    async fn seal<S: Storer>(self, storer: S) -> Result<ByteUnsealable, CryptoError>;
}

#[async_trait]
pub trait Unsealable {
    async fn unseal<S: Storer>(self, storer: S) -> Result<ByteSealable, CryptoError>;
}

pub trait SymmetricSealer {
    type SealedOutput;

    fn seal(
        &self,
        plaintext: BytesSources,
        path: Option<EntryPath>,
    ) -> Result<Self::SealedOutput, CryptoError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    pub fn get_source(&self) -> &BytesSources {
        match self {
            Self::SodiumOxideSymmetricKey(sosku) => &sosku.source,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ByteSealable {
    SodiumOxideSymmetricKey(SodiumOxideSymmetricKeySealable),
}

#[async_trait]
impl Sealable for ByteSealable {
    async fn seal<S: Storer>(self, storer: S) -> Result<ByteUnsealable, CryptoError> {
        match self {
            Self::SodiumOxideSymmetricKey(sosks) => sosks.seal(storer).await,
        }
    }
}

impl ByteSealable {
    pub fn get_source(&self) -> &BytesSources {
        match self {
            Self::SodiumOxideSymmetricKey(sosks) => &sosks.source,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    pub path: EntryPath,
    pub value: States,
}

impl Entry {
    pub fn into_ref(self) -> States {
        States::Referenced {
            builder: match self.value {
                States::Referenced { builder, path: _ } => builder,
                States::Sealed {
                    builder,
                    unsealable: _,
                } => builder,
                States::Unsealed { builder, bytes: _ } => builder,
            },
            path: self.path,
        }
    }
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
        unsealable: ByteUnsealable,
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
    fn into_index() -> Option<Document> {
        None
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
    fn into_index() -> Option<Document> {
        Some(bson::doc! {
        "c": {
            "builder": {
        "t": "Key"
            }
        }
            })
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

impl SymmetricSealer for SymmetricKey {
    type SealedOutput = ByteUnsealable;

    fn seal(
        &self,
        plaintext: BytesSources,
        path: Option<EntryPath>,
    ) -> Result<Self::SealedOutput, CryptoError> {
        match self {
            Self::SodiumOxide(sosk) => Ok(ByteUnsealable::SodiumOxideSymmetricKey(
                sosk.seal(plaintext, path)?,
            )),
        }
    }
}

impl IntoIndex for SymmetricKey {
    fn into_index() -> Option<Document> {
        Some(bson::doc! {
        "c": {
            "builder": {
        "t": "Key",
        "c": {
            "t": "Symmetric"
        }
            }
        }
            })
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
    fn into_index() -> Option<Document> {
        Some(bson::doc! {
        "c": {
            "builder": {
        "t": "Key",
        "c": {
            "t": "Asymmetric",
        }
            }
        }
            })
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
    fn into_index() -> Option<Document> {
        Some(bson::doc! {
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
            })
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
    fn into_index() -> Option<Document> {
        Some(bson::doc! {
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
            })
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

impl Display for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Data::Bool(b) => b.to_string(),
                Data::U64(n) => n.to_string(),
                Data::I64(n) => n.to_string(),
                Data::F64(n) => n.to_string(),
                Data::String(s) => s,
            }
        )
    }
}

impl From<Data> for BytesSources {
    fn from(d: Data) -> BytesSources {
        BytesSources::Vector(VectorBytesSource::new(Some(d.to_string().as_ref())))
    }
}

impl IntoIndex for Data {
    fn into_index() -> Option<Document> {
        Some(bson::doc! {
        "c": {
                    "builder": {
            "t": "Data",
            }
        }
            })
    }
}

impl Buildable for Data {
    type Builder = DataBuilder;

    fn builder(&self) -> Self::Builder {
        DataBuilder {}
    }
}
