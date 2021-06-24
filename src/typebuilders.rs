use crate::{
    keys::sodiumoxide::{
        SodiumOxidePublicAsymmetricKeyBuilder, SodiumOxideSecretAsymmetricKeyBuilder,
        SodiumOxideSymmetricKeyBuilder,
    },
    AsymmetricKey, Builder, CryptoError, Data, Key, PublicAsymmetricKey, SecretAsymmetricKey,
    SymmetricKey, Type,
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, str::FromStr};

/// Need this to provide a level an indirection for TryFrom
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct TypeBuilderContainer(pub TypeBuilder);

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(tag = "t", content = "c")]
pub enum TypeBuilder {
    Data(DataBuilder),
    Key(KeyBuilder),
}

impl TryFrom<TypeBuilderContainer> for TypeBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        Ok(builder.0)
    }
}

impl Builder for TypeBuilder {
    type Output = Type;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        match self {
            Self::Key(k) => Ok(Type::Key(k.build(bytes)?)),
            Self::Data(d) => Ok(Type::Data(d.build(bytes)?)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(tag = "t", content = "c")]
pub enum KeyBuilder {
    Symmetric(SymmetricKeyBuilder),
    Asymmetric(AsymmetricKeyBuilder),
}

impl TryFrom<TypeBuilderContainer> for KeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
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
#[serde(tag = "t", content = "c")]
pub enum SymmetricKeyBuilder {
    SodiumOxide(SodiumOxideSymmetricKeyBuilder),
}

impl TryFrom<TypeBuilderContainer> for SymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
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
#[serde(tag = "t", content = "c")]
pub enum AsymmetricKeyBuilder {
    Public(PublicAsymmetricKeyBuilder),
    Secret(SecretAsymmetricKeyBuilder),
}

impl TryFrom<TypeBuilderContainer> for AsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
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
#[serde(tag = "t", content = "c")]
pub enum PublicAsymmetricKeyBuilder {
    SodiumOxide(SodiumOxidePublicAsymmetricKeyBuilder),
}

impl TryFrom<TypeBuilderContainer> for PublicAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
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
#[serde(tag = "t", content = "c")]
pub enum SecretAsymmetricKeyBuilder {
    SodiumOxide(SodiumOxideSecretAsymmetricKeyBuilder),
}

impl TryFrom<TypeBuilderContainer> for SecretAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
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
#[serde(tag = "t", content = "c")]
pub enum DataBuilder {
    Bool(BoolDataBuilder),
    U64(U64DataBuilder),
    I64(I64DataBuilder),
    F64(F64DataBuilder),
    String(StringDataBuilder),
}

impl TryFrom<TypeBuilderContainer> for DataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(db) => Ok(db),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for DataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        match self {
            Self::Bool(bdb) => bdb.build(bytes),
            Self::U64(ndb) => ndb.build(bytes),
            Self::I64(ndb) => ndb.build(bytes),
            Self::F64(ndb) => ndb.build(bytes),
            Self::String(sdb) => sdb.build(bytes),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct BoolDataBuilder {}

impl TryFrom<TypeBuilderContainer> for BoolDataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::Bool(bdb)) => Ok(bdb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for BoolDataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        let b = bool::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        Ok(Data::Bool(b))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct U64DataBuilder {}

impl TryFrom<TypeBuilderContainer> for U64DataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::U64(ndb)) => Ok(ndb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for U64DataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        let n = u64::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        Ok(Data::U64(n))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct I64DataBuilder {}

impl TryFrom<TypeBuilderContainer> for I64DataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::I64(ndb)) => Ok(ndb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for I64DataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        let n = i64::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        Ok(Data::I64(n))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct F64DataBuilder {}

impl TryFrom<TypeBuilderContainer> for F64DataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::F64(ndb)) => Ok(ndb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for F64DataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        let n = f64::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        Ok(Data::F64(n))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct StringDataBuilder {}

impl TryFrom<TypeBuilderContainer> for StringDataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::String(sdb)) => Ok(sdb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for StringDataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        Ok(Data::String(s))
    }
}
