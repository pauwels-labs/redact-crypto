pub mod sodiumoxide;

use self::sodiumoxide::{
    SodiumOxidePublicAsymmetricKey, SodiumOxidePublicAsymmetricKeyBuilder,
    SodiumOxideSecretAsymmetricKey, SodiumOxideSecretAsymmetricKeyBuilder, SodiumOxideSymmetricKey,
    SodiumOxideSymmetricKeyBuilder,
};
use crate::{
    Builder, ByteSource, ByteUnsealable, CryptoError, EntryPath, HasBuilder, HasByteSource,
    HasIndex, SymmetricNonce, TypeBuilder, TypeBuilderContainer,
};
use mongodb::bson::{self, Document};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub trait SymmetricSealer {
    type SealedOutput;
    type Nonce;

    fn seal(
        &self,
        plaintext: ByteSource,
        nonce: Option<&Self::Nonce>,
        key_path: Option<EntryPath>,
    ) -> Result<Self::SealedOutput, CryptoError>;
}

pub trait SymmetricUnsealer {
    type UnsealedOutput;
    type Nonce;

    fn unseal(
        &self,
        ciphertext: ByteSource,
        nonce: &Self::Nonce,
        key_path: Option<EntryPath>,
    ) -> Result<Self::UnsealedOutput, CryptoError>;
}

pub trait SecretAsymmetricSealer {
    type SealedOutput;
    type Nonce;
    type PublicKey;

    fn seal(
        &self,
        plaintext: ByteSource,
        public_key: Option<&Self::PublicKey>,
        nonce: Option<&Self::Nonce>,
        key_path: Option<EntryPath>,
    ) -> Result<Self::SealedOutput, CryptoError>;
}

pub trait SecretAsymmetricUnsealer {
    type UnsealedOutput;
    type Nonce;
    type PublicKey;

    fn unseal(
        &self,
        ciphertext: ByteSource,
        public_key: Option<&Self::PublicKey>,
        nonce: &Self::Nonce,
        key_path: Option<EntryPath>,
    ) -> Result<Self::UnsealedOutput, CryptoError>;
}

pub trait PublicAsymmetricSealer {
    type SealedOutput;
    type Nonce;
    type SecretKey;

    fn seal(
        &self,
        plaintext: ByteSource,
        secret_key: &Self::SecretKey,
        nonce: Option<&Self::Nonce>,
        key_path: Option<EntryPath>,
    ) -> Result<Self::SealedOutput, CryptoError>;
}

pub trait PublicAsymmetricUnsealer {
    type UnsealedOutput;
    type Nonce;
    type SecretKey;

    fn unseal(
        &self,
        ciphertext: ByteSource,
        secret_key: &Self::SecretKey,
        nonce: &Self::Nonce,
        key_path: Option<EntryPath>,
    ) -> Result<Self::UnsealedOutput, CryptoError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum Key {
    Symmetric(SymmetricKey),
    Asymmetric(AsymmetricKey),
}

impl HasIndex for Key {
    type Index = Document;

    fn get_index() -> Option<Self::Index> {
        Some(bson::doc! {
        "c": {
            "builder": {
        "t": "Key"
            }
        }
            })
    }
}

impl HasBuilder for Key {
    type Builder = KeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::Symmetric(sk) => KeyBuilder::Symmetric(sk.builder()),
            Self::Asymmetric(ak) => KeyBuilder::Asymmetric(ak.builder()),
        }
    }
}

impl HasByteSource for Key {
    fn byte_source(&self) -> ByteSource {
        match self {
            Self::Symmetric(sk) => sk.byte_source(),
            Self::Asymmetric(ak) => ak.byte_source(),
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

impl From<KeyBuilder> for TypeBuilder {
    fn from(kb: KeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(kb)
    }
}

impl Builder for KeyBuilder {
    type Output = Key;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match self {
            Self::Symmetric(sk) => Ok(Key::Symmetric(sk.build(bytes)?)),
            Self::Asymmetric(ak) => Ok(Key::Asymmetric(ak.build(bytes)?)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum SymmetricKey {
    SodiumOxide(SodiumOxideSymmetricKey),
}

impl SymmetricSealer for SymmetricKey {
    type SealedOutput = ByteUnsealable;
    type Nonce = SymmetricNonce;

    fn seal(
        &self,
        plaintext: ByteSource,
        nonce: Option<&Self::Nonce>,
        path: Option<EntryPath>,
    ) -> Result<Self::SealedOutput, CryptoError> {
        match self {
            Self::SodiumOxide(sosk) => {
                let nonce = match nonce {
                    Some(n) => match n {
                        SymmetricNonce::SodiumOxide(sosn) => Ok::<_, CryptoError>(Some(sosn)),
                    },
                    None => Ok(None),
                }?;
                Ok(ByteUnsealable::SodiumOxideSymmetricKey(
                    sosk.seal(plaintext, nonce, path)?,
                ))
            }
        }
    }
}

impl HasIndex for SymmetricKey {
    type Index = Document;

    fn get_index() -> Option<Self::Index> {
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

impl HasBuilder for SymmetricKey {
    type Builder = SymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::SodiumOxide(sosk) => SymmetricKeyBuilder::SodiumOxide(sosk.builder()),
        }
    }
}

impl HasByteSource for SymmetricKey {
    fn byte_source(&self) -> ByteSource {
        match self {
            Self::SodiumOxide(sosk) => sosk.byte_source(),
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

impl From<SymmetricKeyBuilder> for TypeBuilder {
    fn from(skb: SymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Symmetric(skb))
    }
}

impl Builder for SymmetricKeyBuilder {
    type Output = SymmetricKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match self {
            Self::SodiumOxide(soskb) => Ok(SymmetricKey::SodiumOxide(soskb.build(bytes)?)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum AsymmetricKey {
    Public(PublicAsymmetricKey),
    Secret(SecretAsymmetricKey),
}

impl HasIndex for AsymmetricKey {
    type Index = Document;

    fn get_index() -> Option<Self::Index> {
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

impl HasBuilder for AsymmetricKey {
    type Builder = AsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::Public(pak) => AsymmetricKeyBuilder::Public(pak.builder()),
            Self::Secret(sak) => AsymmetricKeyBuilder::Secret(sak.builder()),
        }
    }
}

impl HasByteSource for AsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        match self {
            Self::Public(pak) => pak.byte_source(),
            Self::Secret(sak) => sak.byte_source(),
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

impl From<AsymmetricKeyBuilder> for TypeBuilder {
    fn from(akb: AsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(akb))
    }
}

impl Builder for AsymmetricKeyBuilder {
    type Output = AsymmetricKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match self {
            Self::Public(pakb) => Ok(AsymmetricKey::Public(pakb.build(bytes)?)),
            Self::Secret(sakb) => Ok(AsymmetricKey::Secret(sakb.build(bytes)?)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum PublicAsymmetricKey {
    SodiumOxide(SodiumOxidePublicAsymmetricKey),
}

impl HasIndex for PublicAsymmetricKey {
    type Index = Document;

    fn get_index() -> Option<Self::Index> {
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

impl HasBuilder for PublicAsymmetricKey {
    type Builder = PublicAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::SodiumOxide(sopak) => PublicAsymmetricKeyBuilder::SodiumOxide(sopak.builder()),
        }
    }
}

impl HasByteSource for PublicAsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        match self {
            Self::SodiumOxide(sopak) => sopak.byte_source(),
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

impl From<PublicAsymmetricKeyBuilder> for TypeBuilder {
    fn from(pakb: PublicAsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(pakb)))
    }
}

impl Builder for PublicAsymmetricKeyBuilder {
    type Output = PublicAsymmetricKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match self {
            Self::SodiumOxide(sopakb) => Ok(PublicAsymmetricKey::SodiumOxide(sopakb.build(bytes)?)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum SecretAsymmetricKey {
    SodiumOxide(SodiumOxideSecretAsymmetricKey),
}

impl HasIndex for SecretAsymmetricKey {
    type Index = Document;

    fn get_index() -> Option<Self::Index> {
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

impl HasBuilder for SecretAsymmetricKey {
    type Builder = SecretAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::SodiumOxide(sosak) => SecretAsymmetricKeyBuilder::SodiumOxide(sosak.builder()),
        }
    }
}

impl HasByteSource for SecretAsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        match self {
            Self::SodiumOxide(sosak) => sosak.byte_source(),
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

impl From<SecretAsymmetricKeyBuilder> for TypeBuilder {
    fn from(sakb: SecretAsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(sakb)))
    }
}

impl Builder for SecretAsymmetricKeyBuilder {
    type Output = SecretAsymmetricKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match self {
            Self::SodiumOxide(sosakb) => Ok(SecretAsymmetricKey::SodiumOxide(sosakb.build(bytes)?)),
        }
    }
}
