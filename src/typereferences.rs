use crate::{
    keys::sodiumoxide::{
        SodiumOxidePublicAsymmetricKeyReference, SodiumOxideSecretAsymmetricKeyReference,
        SodiumOxideSymmetricKeyReference,
    },
    CryptoError,
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_type")]
pub enum TypeReferences {
    Keys(KeyTypeReferences),
    Data(DataTypeReferences),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_key_type")]
pub enum KeyTypeReferences {
    Symmetric(SymmetricKeyTypeReferences),
    Asymmetric(AsymmetricKeyTypeReferences),
}

impl TryFrom<TypeReferences> for KeyTypeReferences {
    type Error = CryptoError;

    fn try_from(value: TypeReferences) -> Result<Self, Self::Error> {
        match value {
            TypeReferences::Keys(ktr) => Ok(ktr),
            TypeReferences::Data(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_symmetric_key_type")]
pub enum SymmetricKeyTypeReferences {
    SodiumOxide(SodiumOxideSymmetricKeyReference),
}

impl TryFrom<TypeReferences> for SymmetricKeyTypeReferences {
    type Error = CryptoError;

    fn try_from(value: TypeReferences) -> Result<Self, Self::Error> {
        let ktr: KeyTypeReferences = KeyTypeReferences::try_from(value)?;
        match ktr {
            KeyTypeReferences::Symmetric(sktr) => Ok(sktr),
            KeyTypeReferences::Asymmetric(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_asymmetric_key_type")]
pub enum AsymmetricKeyTypeReferences {
    Public(PublicAsymmetricKeyTypeReferences),
    Secret(SecretAsymmetricKeyTypeReferences),
}

impl TryFrom<TypeReferences> for AsymmetricKeyTypeReferences {
    type Error = CryptoError;

    fn try_from(value: TypeReferences) -> Result<Self, Self::Error> {
        let ktr: KeyTypeReferences = KeyTypeReferences::try_from(value)?;
        match ktr {
            KeyTypeReferences::Asymmetric(aktr) => Ok(aktr),
            KeyTypeReferences::Symmetric(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_public_asymmetric_key_type")]
pub enum PublicAsymmetricKeyTypeReferences {
    SodiumOxide(SodiumOxidePublicAsymmetricKeyReference),
}

impl TryFrom<TypeReferences> for PublicAsymmetricKeyTypeReferences {
    type Error = CryptoError;

    fn try_from(value: TypeReferences) -> Result<Self, Self::Error> {
        let aktr: AsymmetricKeyTypeReferences = AsymmetricKeyTypeReferences::try_from(value)?;
        match aktr {
            AsymmetricKeyTypeReferences::Public(paktr) => Ok(paktr),
            AsymmetricKeyTypeReferences::Secret(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "sealed_secret_asymmetric_key_type")]
pub enum SecretAsymmetricKeyTypeReferences {
    SodiumOxide(SodiumOxideSecretAsymmetricKeyReference),
}

impl TryFrom<TypeReferences> for SecretAsymmetricKeyTypeReferences {
    type Error = CryptoError;

    fn try_from(value: TypeReferences) -> Result<Self, Self::Error> {
        let aktr: AsymmetricKeyTypeReferences = AsymmetricKeyTypeReferences::try_from(value)?;
        match aktr {
            AsymmetricKeyTypeReferences::Secret(saktr) => Ok(saktr),
            AsymmetricKeyTypeReferences::Public(_) => Err(CryptoError::NotDowncastable),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DataTypeReferences {
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    String(String),
}
