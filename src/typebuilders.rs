use crate::{
    keys::sodiumoxide::{
        SodiumOxidePublicAsymmetricKeyBuilder, SodiumOxideSecretAsymmetricKeyBuilder,
        SodiumOxideSymmetricKeyBuilder,
    },
    AsymmetricKey, Builder, CryptoError, Data, Key, PublicAsymmetricKey, SecretAsymmetricKey,
    SymmetricKey,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum TypeBuilder {
    Data(DataBuilder),
    Key(KeyBuilder),
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum KeyBuilder {
    Symmetric(SymmetricKeyBuilder),
    Asymmetric(AsymmetricKeyBuilder),
}

impl TryFrom<TypeBuilder> for KeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
            TypeBuilder::Key(kb) => Ok(kb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for KeyBuilder {
    type Output = Key;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        match self {
            Self::Symmetric(sk) => Ok(Key::Symmetric(sk.build(bytes)?)),
            Self::Asymmetric(ak) => Ok(Key::Asymmetric(ak.build(bytes)?)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum SymmetricKeyBuilder {
    SodiumOxide(SodiumOxideSymmetricKeyBuilder),
}

impl TryFrom<TypeBuilder> for SymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
            TypeBuilder::Key(KeyBuilder::Symmetric(skb)) => Ok(skb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for SymmetricKeyBuilder {
    type Output = SymmetricKey;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        match self {
            Self::SodiumOxide(soskb) => Ok(SymmetricKey::SodiumOxide(soskb.build(bytes)?)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum AsymmetricKeyBuilder {
    Public(PublicAsymmetricKeyBuilder),
    Secret(SecretAsymmetricKeyBuilder),
}

impl TryFrom<TypeBuilder> for AsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
            TypeBuilder::Key(KeyBuilder::Asymmetric(akb)) => Ok(akb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for AsymmetricKeyBuilder {
    type Output = AsymmetricKey;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        match self {
            Self::Public(pakb) => Ok(AsymmetricKey::Public(pakb.build(bytes)?)),
            Self::Secret(sakb) => Ok(AsymmetricKey::Secret(sakb.build(bytes)?)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum PublicAsymmetricKeyBuilder {
    SodiumOxide(SodiumOxidePublicAsymmetricKeyBuilder),
}

impl TryFrom<TypeBuilder> for PublicAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(pakb))) => {
                Ok(pakb)
            }
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for PublicAsymmetricKeyBuilder {
    type Output = PublicAsymmetricKey;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        match self {
            Self::SodiumOxide(sopakb) => Ok(PublicAsymmetricKey::SodiumOxide(sopakb.build(bytes)?)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum SecretAsymmetricKeyBuilder {
    SodiumOxide(SodiumOxideSecretAsymmetricKeyBuilder),
}

impl TryFrom<TypeBuilder> for SecretAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(sakb))) => {
                Ok(sakb)
            }
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for SecretAsymmetricKeyBuilder {
    type Output = SecretAsymmetricKey;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        match self {
            Self::SodiumOxide(sosakb) => Ok(SecretAsymmetricKey::SodiumOxide(sosakb.build(bytes)?)),
        }
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
