use crate::{
    keys::sodiumoxide::{
        SodiumOxidePublicAsymmetricKey, SodiumOxideSecretAsymmetricKey, SodiumOxideSymmetricKey,
    },
    AsymmetricKeyTypeReferences, BytesSources, CryptoError, KeyName, KeyTypeReferences,
    PublicAsymmetricKeyTypeReferences, SealedAsymmetricKeyTypes, SealedKeyTypes,
    SealedPublicAsymmetricKeyTypes, SealedSecretAsymmetricKeyTypes, SealedSymmetricKeyTypes,
    SealedTypes, SecretAsymmetricKeyTypeReferences, StorerWithType, SymmetricKeyTypeReferences,
    TypeReferences,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Debug};

pub trait Sealer {
    fn try_seal(&self, source: BytesSources) -> Result<BytesSources, CryptoError>;
    fn get_key(&self) -> KeyTypes;
}

pub trait Sealable {
    type SealedType: Unsealable;

    fn try_seal(&self, sealer: Box<dyn Sealer>) -> Result<Self::SealedType, CryptoError>;
}

pub trait Unsealer {
    fn try_unseal(&self, source: BytesSources) -> Result<BytesSources, CryptoError>;
    fn get_key(&self) -> KeyTypes;
}

pub trait Unsealable {
    type UnsealedType: Sealable;

    fn try_unseal(&self, unsealer: Box<dyn Unsealer>) -> Result<Self::UnsealedType, CryptoError>;
    fn get_type(&self) -> Types;
}

pub trait Fetchable {
    type FetchedType;

    fn try_fetch(
        &self,
        store: Box<dyn StorerWithType<Self::FetchedType>>,
    ) -> Result<Self::FetchedType, CryptoError>;
    fn get_type(&self) -> Types;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry<U: Stateful> {
    pub name: KeyName,
    pub value: TypeStates<U>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TypeStates<U: Stateful> {
    Reference(U::ReferenceType),
    Sealed(U::SealedType),
    Unsealed(U::UnsealedType),
}

pub trait Stateful {
    type ReferenceType: TryFrom<TypeReferences>
        + Send
        + Serialize
        + DeserializeOwned
        + Debug
        + Clone;
    type SealedType: TryFrom<SealedTypes> + Send + Serialize + DeserializeOwned + Debug + Clone;
    type UnsealedType: TryFrom<Types> + Send + Serialize + DeserializeOwned + Debug + Clone;
}

// pub enum TypeStates<U> {
//     Reference(Box<dyn Fetchable<FetchedType = TypeStates<U>>>),
//     Sealed(Box<dyn Unsealable<UnsealedType = U>>),
//     Unsealed(U),
// }

// pub enum TypeStates<R, S, U> {
//     Reference(R),
//     Sealed(S),
//     Unsealed(U),
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub enum TypeStates<S, U, R>
// where
//     S: Unsealable<UnsealedType = U>,
//     R: Fetchable<FetchedType = TypeStates<S, U, R>>,
// {
//     Sealed(S),
//     Unsealed(U),
//     Reference(R),
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TypeCollection<T>(Vec<T>);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum Types {
    Keys(KeyTypes),
    Data(DataTypes),
}

impl Stateful for Types {
    type ReferenceType = TypeReferences;
    type SealedType = SealedTypes;
    type UnsealedType = Self;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "key_type")]
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

impl Stateful for KeyTypes {
    type ReferenceType = KeyTypeReferences;
    type SealedType = SealedKeyTypes;
    type UnsealedType = Self;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "symmetric_key_type")]
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

impl Stateful for SymmetricKeyTypes {
    type ReferenceType = SymmetricKeyTypeReferences;
    type SealedType = SealedSymmetricKeyTypes;
    type UnsealedType = Self;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "asymmetric_key_type")]
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

impl Stateful for AsymmetricKeyTypes {
    type ReferenceType = AsymmetricKeyTypeReferences;
    type SealedType = SealedAsymmetricKeyTypes;
    type UnsealedType = Self;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "public_asymmetric_key_type")]
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

impl Stateful for PublicAsymmetricKeyTypes {
    type ReferenceType = PublicAsymmetricKeyTypeReferences;
    type SealedType = SealedPublicAsymmetricKeyTypes;
    type UnsealedType = Self;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "secret_asymmetric_key_type")]
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

impl Stateful for SecretAsymmetricKeyTypes {
    type ReferenceType = SecretAsymmetricKeyTypeReferences;
    type SealedType = SealedSecretAsymmetricKeyTypes;
    type UnsealedType = Self;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DataTypes {
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    String(String),
}
