pub mod ring;
pub mod sodiumoxide;

use self::{
    ring::{
        RingEd25519PublicAsymmetricKey, RingEd25519PublicAsymmetricKeyBuilder,
        RingEd25519SecretAsymmetricKey, RingEd25519SecretAsymmetricKeyBuilder,
    },
    sodiumoxide::{
        SodiumOxideCurve25519PublicAsymmetricKey, SodiumOxideCurve25519PublicAsymmetricKeyBuilder,
        SodiumOxideCurve25519SecretAsymmetricKey, SodiumOxideCurve25519SecretAsymmetricKeyBuilder,
        SodiumOxideEd25519PublicAsymmetricKey, SodiumOxideEd25519PublicAsymmetricKeyBuilder,
        SodiumOxideEd25519SecretAsymmetricKey, SodiumOxideEd25519SecretAsymmetricKeyBuilder,
        SodiumOxideSymmetricKey, SodiumOxideSymmetricKeyBuilder,
    },
};
use crate::{
    Builder, ByteAlgorithm, ByteSource, CryptoError, Entry, HasBuilder, HasByteSource, HasIndex,
    StorableType, SymmetricNonce, TypeBuilder, TypeBuilderContainer,
};
use async_trait::async_trait;
use futures::Future;
use mongodb::bson::{self, Document};
use serde::{Deserialize, Serialize, Serializer};
use spki::AlgorithmIdentifier;
use std::convert::TryFrom;
use serde::ser::{SerializeStruct, SerializeMap};

pub trait Signer {
    fn sign(&self, bytes: ByteSource) -> Result<ByteSource, CryptoError>;
}

pub trait Verifier {
    fn verify(&self, msg: ByteSource, signature: ByteSource) -> Result<(), CryptoError>;
}

#[async_trait]
pub trait ToSymmetricByteAlgorithm {
    type Key: StorableType;
    type Nonce;

    async fn to_byte_algorithm<F, Fut>(
        self,
        nonce: Option<Self::Nonce>,
        f: F,
    ) -> Result<ByteAlgorithm, CryptoError>
    where
        F: FnOnce(Self::Key) -> Fut + Send,
        Fut: Future<Output = Result<Entry<Self::Key>, CryptoError>> + Send;
}

pub trait SymmetricSealer {
    type SealedOutput;
    type Nonce;

    fn seal(
        &self,
        plaintext: &ByteSource,
        nonce: Option<&Self::Nonce>,
    ) -> Result<(Self::SealedOutput, Self::Nonce), CryptoError>;
}

pub trait SymmetricUnsealer {
    type UnsealedOutput;
    type Nonce;

    fn unseal(
        &self,
        ciphertext: &ByteSource,
        nonce: &Self::Nonce,
    ) -> Result<Self::UnsealedOutput, CryptoError>;
}

#[async_trait]
pub trait ToSecretAsymmetricByteAlgorithm {
    type SecretKey: StorableType;
    type Nonce;
    type PublicKey;

    async fn to_byte_algorithm<F, Fut>(
        self,
        public_key: Option<Entry<Self::PublicKey>>,
        nonce: Option<Self::Nonce>,
        f: F,
    ) -> Result<ByteAlgorithm, CryptoError>
    where
        F: FnOnce(Self::SecretKey) -> Fut + Send,
        Fut: Future<Output = Result<Entry<Self::SecretKey>, CryptoError>> + Send;
}

pub trait SecretAsymmetricSealer {
    type SealedOutput;
    type Nonce;
    type PublicKey;

    fn seal(
        &self,
        plaintext: &ByteSource,
        public_key: Option<&Self::PublicKey>,
        nonce: Option<&Self::Nonce>,
    ) -> Result<(Self::SealedOutput, Self::Nonce), CryptoError>;
}

pub trait SecretAsymmetricUnsealer {
    type UnsealedOutput;
    type Nonce;
    type PublicKey;

    fn unseal(
        &self,
        ciphertext: &ByteSource,
        public_key: Option<&Self::PublicKey>,
        nonce: &Self::Nonce,
    ) -> Result<Self::UnsealedOutput, CryptoError>;
}

#[async_trait]
pub trait ToPublicAsymmetricByteAlgorithm {
    type SecretKey;
    type Nonce;
    type PublicKey: StorableType;

    async fn to_byte_algorithm<F, Fut>(
        self,
        secret_key: Entry<Self::SecretKey>,
        nonce: Option<Self::Nonce>,
        f: F,
    ) -> Result<ByteAlgorithm, CryptoError>
    where
        F: FnOnce(Self::PublicKey) -> Fut + Send,
        Fut: Future<Output = Result<Entry<Self::PublicKey>, CryptoError>> + Send;
}

pub trait PublicAsymmetricSealer {
    type SealedOutput;
    type Nonce;
    type SecretKey;

    fn seal(
        &self,
        plaintext: &ByteSource,
        secret_key: &Self::SecretKey,
        nonce: Option<&Self::Nonce>,
    ) -> Result<(Self::SealedOutput, Self::Nonce), CryptoError>;
}

pub trait PublicAsymmetricUnsealer {
    type UnsealedOutput;
    type Nonce;
    type SecretKey;

    fn unseal(
        &self,
        ciphertext: &ByteSource,
        secret_key: &Self::SecretKey,
        nonce: &Self::Nonce,
    ) -> Result<Self::UnsealedOutput, CryptoError>;
}

pub trait HasPublicKey {
    type PublicKey: HasByteSource;

    fn public_key(&self) -> Result<Self::PublicKey, CryptoError>;
}

pub trait HasAlgorithmIdentifier {
    fn algorithm_identifier<'a>(&self) -> AlgorithmIdentifier<'a>;
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Key {
    Symmetric(SymmetricKey),
    Asymmetric(AsymmetricKey),
}

impl StorableType for Key {}

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

#[derive(Serialize, Deserialize, Debug)]
pub enum SymmetricKey {
    SodiumOxide(SodiumOxideSymmetricKey),
}

#[async_trait]
impl ToSymmetricByteAlgorithm for SymmetricKey {
    type Key = SymmetricKey;
    type Nonce = SymmetricNonce;

    async fn to_byte_algorithm<F, Fut>(
        self,
        nonce: Option<Self::Nonce>,
        f: F,
    ) -> Result<ByteAlgorithm, CryptoError>
    where
        F: FnOnce(Self::Key) -> Fut + Send,
        Fut: Future<Output = Result<Entry<Self::Key>, CryptoError>> + Send,
    {
        match self {
            SymmetricKey::SodiumOxide(sosk) => {
                let nonce = nonce.map(|n| match n {
                    SymmetricNonce::SodiumOxide(sosn) => sosn,
                });
                sosk.to_byte_algorithm(nonce, |key| async move {
                    f(SymmetricKey::SodiumOxide(key))
                        .await?
                        .cast::<SodiumOxideSymmetricKey>()
                })
                .await
            }
        }
    }
}

impl StorableType for SymmetricKey {}

impl SymmetricSealer for SymmetricKey {
    type SealedOutput = ByteSource;
    type Nonce = SymmetricNonce;

    fn seal(
        &self,
        plaintext: &ByteSource,
        nonce: Option<&Self::Nonce>,
    ) -> Result<(Self::SealedOutput, Self::Nonce), CryptoError> {
        match self {
            Self::SodiumOxide(sosk) => {
                let nonce = nonce.map(|n| match n {
                    SymmetricNonce::SodiumOxide(sosn) => sosn,
                });
                let (output, nonce) = sosk.seal(plaintext, nonce)?;
                Ok((output, SymmetricNonce::SodiumOxide(nonce)))
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

#[derive(Serialize, Deserialize, Debug)]
pub enum AsymmetricKey {
    Public(PublicAsymmetricKey),
    Secret(SecretAsymmetricKey),
}

impl StorableType for AsymmetricKey {}

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

#[derive(Serialize, Deserialize, Debug)]
pub enum PublicAsymmetricKey {
    SodiumOxideCurve25519(SodiumOxideCurve25519PublicAsymmetricKey),
    SodiumOxideEd25519(SodiumOxideEd25519PublicAsymmetricKey),
    RingEd25519(RingEd25519PublicAsymmetricKey),
}

impl StorableType for PublicAsymmetricKey {}

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
            PublicAsymmetricKey::SodiumOxideCurve25519(sopak) => {
                PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(sopak.builder())
            }
            PublicAsymmetricKey::SodiumOxideEd25519(sopak) => {
                PublicAsymmetricKeyBuilder::SodiumOxideEd25519(sopak.builder())
            }
            PublicAsymmetricKey::RingEd25519(rpak) => {
                PublicAsymmetricKeyBuilder::RingEd25519(rpak.builder())
            }
        }
    }
}

impl HasByteSource for PublicAsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        match self {
            PublicAsymmetricKey::SodiumOxideCurve25519(sopak) => sopak.byte_source(),
            PublicAsymmetricKey::SodiumOxideEd25519(sopak) => sopak.byte_source(),
            PublicAsymmetricKey::RingEd25519(rpak) => rpak.byte_source(),
        }
    }
}

impl HasAlgorithmIdentifier for PublicAsymmetricKey {
    fn algorithm_identifier<'a>(&self) -> AlgorithmIdentifier<'a> {
        match self {
            PublicAsymmetricKey::SodiumOxideCurve25519(k) => k.algorithm_identifier(),
            PublicAsymmetricKey::SodiumOxideEd25519(k) => k.algorithm_identifier(),
            PublicAsymmetricKey::RingEd25519(k) => k.algorithm_identifier(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(tag = "t", content = "c")]
pub enum PublicAsymmetricKeyBuilder {
    SodiumOxideCurve25519(SodiumOxideCurve25519PublicAsymmetricKeyBuilder),
    SodiumOxideEd25519(SodiumOxideEd25519PublicAsymmetricKeyBuilder),
    RingEd25519(RingEd25519PublicAsymmetricKeyBuilder),
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
            PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(sopakb) => Ok(
                PublicAsymmetricKey::SodiumOxideCurve25519(sopakb.build(bytes)?),
            ),
            PublicAsymmetricKeyBuilder::SodiumOxideEd25519(sopakb) => Ok(
                PublicAsymmetricKey::SodiumOxideEd25519(sopakb.build(bytes)?),
            ),
            PublicAsymmetricKeyBuilder::RingEd25519(rpakb) => {
                Ok(PublicAsymmetricKey::RingEd25519(rpakb.build(bytes)?))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SecretAsymmetricKey {
    SodiumOxideCurve25519(SodiumOxideCurve25519SecretAsymmetricKey),
    SodiumOxideEd25519(SodiumOxideEd25519SecretAsymmetricKey),
    RingEd25519(RingEd25519SecretAsymmetricKey),
}

impl StorableType for SecretAsymmetricKey {}

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
            SecretAsymmetricKey::SodiumOxideCurve25519(sosak) => {
                SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(sosak.builder())
            }
            SecretAsymmetricKey::SodiumOxideEd25519(sosak) => {
                SecretAsymmetricKeyBuilder::SodiumOxideEd25519(sosak.builder())
            }
            SecretAsymmetricKey::RingEd25519(rsak) => {
                SecretAsymmetricKeyBuilder::RingEd25519(rsak.builder())
            }
        }
    }
}

impl HasByteSource for SecretAsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        match self {
            SecretAsymmetricKey::SodiumOxideCurve25519(sosak) => sosak.byte_source(),
            SecretAsymmetricKey::SodiumOxideEd25519(sosak) => sosak.byte_source(),
            SecretAsymmetricKey::RingEd25519(rsak) => rsak.byte_source(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum SigningKey {
    SodiumOxideEd25519(SodiumOxideEd25519SecretAsymmetricKey),
    RingEd25519(RingEd25519SecretAsymmetricKey),
}

impl From<SigningKey> for Key {
    fn from(signing_key: SigningKey) -> Self {
        match signing_key {
            SigningKey::SodiumOxideEd25519(k) =>
                Key::Asymmetric(AsymmetricKey::Public(PublicAsymmetricKey::SodiumOxideEd25519(k.public_key().unwrap()))),
            SigningKey::RingEd25519(k) =>
                Key::Asymmetric(AsymmetricKey::Public(PublicAsymmetricKey::RingEd25519(k.public_key().unwrap())))
        }
    }
}

// impl Serialize for SigningKey {
//     fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
//         S: Serializer {
//         match self {
//             SigningKey::SodiumOxideEd25519(sosak) => {
//                 let sosak = SodiumOxideEd25519SecretAsymmetricKey { secret_key: sk };
//
//             },
//             SigningKey::RingEd25519(rsak) => {
//                 SigningKeyBuilder::RingEd25519(rsak.builder())
//             }
//         }
//     }
// }

impl StorableType for SigningKey {}

#[derive(Serialize, Deserialize, Debug)]
pub enum EncryptingKey {
    SodiumOxideCurve25519(SodiumOxideCurve25519SecretAsymmetricKey),
    SodiumOxideSymmetricKey(SodiumOxideSymmetricKey),
}

// #[derive(Serialize, Deserialize, Debug)]
// pub enum SigningAndEncryptingKey {
//     SodiumOxideEd25519(SodiumOxideEd25519SecretAsymmetricKey),
// }

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(tag = "t", content = "c")]
pub enum SigningKeyBuilder {
    SodiumOxideEd25519(SodiumOxideEd25519SecretAsymmetricKeyBuilder),
    RingEd25519(RingEd25519SecretAsymmetricKeyBuilder),
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(tag = "t", content = "c")]
pub enum EncryptingKeyBuilder {
    SodiumOxideCurve25519(SodiumOxideCurve25519SecretAsymmetricKeyBuilder),
    SodiumOxideSymmetricKey(SodiumOxideSymmetricKeyBuilder),
}

//
// #[derive(Serialize, Deserialize, Debug, Copy, Clone)]
// #[serde(tag = "t", content = "c")]
// pub enum SigningAndEncryptingKeyBuilder {
// }

impl HasIndex for SigningKey {
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

impl HasBuilder for SigningKey {
    type Builder = SigningKeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            SigningKey::SodiumOxideEd25519(sosak) => {
                SigningKeyBuilder::SodiumOxideEd25519(sosak.builder())
            },
            SigningKey::RingEd25519(rsak) => {
                SigningKeyBuilder::RingEd25519(rsak.builder())
            }
        }
    }
}

impl HasBuilder for EncryptingKey {
    type Builder = EncryptingKeyBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            EncryptingKey::SodiumOxideCurve25519(sosak) => {
                EncryptingKeyBuilder::SodiumOxideCurve25519(sosak.builder())
            },
            EncryptingKey::SodiumOxideSymmetricKey(ssk) => {
                EncryptingKeyBuilder::SodiumOxideSymmetricKey(ssk.builder())
            }
        }
    }
}

impl TryFrom<TypeBuilderContainer> for SigningKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(SecretAsymmetricKeyBuilder::SodiumOxideEd25519(sosak)))) => {
                Ok(SigningKeyBuilder::SodiumOxideEd25519(sosak))
            },
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(SecretAsymmetricKeyBuilder::RingEd25519(rsak)))) => {
                Ok(SigningKeyBuilder::RingEd25519(rsak))
            }
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl TryFrom<TypeBuilderContainer> for EncryptingKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(sosak)))) => {
                Ok(EncryptingKeyBuilder::SodiumOxideCurve25519(sosak))
            },
            TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(ssk))) => {
                Ok(EncryptingKeyBuilder::SodiumOxideSymmetricKey(ssk))
            }
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl From<SigningKeyBuilder> for TypeBuilder {
    fn from(skb: SigningKeyBuilder) -> TypeBuilder {
        match skb {
            SigningKeyBuilder::SodiumOxideEd25519(b) => b.into(),
            SigningKeyBuilder::RingEd25519(b) => b.into(),
        }
    }
}

impl From<EncryptingKeyBuilder> for TypeBuilder {
    fn from(ekb: EncryptingKeyBuilder) -> TypeBuilder {
        match ekb {
            EncryptingKeyBuilder::SodiumOxideCurve25519(b) => b.into(),
            EncryptingKeyBuilder::SodiumOxideSymmetricKey(b) => b.into(),
        }
    }
}

impl Builder for SigningKeyBuilder {
    type Output = SigningKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match self {
            Self::SodiumOxideEd25519(sk) => Ok(SigningKey::SodiumOxideEd25519(sk.build(bytes)?)),
            Self::RingEd25519(rk) => Ok(SigningKey::RingEd25519(rk.build(bytes)?)),
        }
    }
}

impl Builder for EncryptingKeyBuilder {
    type Output = EncryptingKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match self {
            Self::SodiumOxideCurve25519(sk) => Ok(EncryptingKey::SodiumOxideCurve25519(sk.build(bytes)?)),
            Self::SodiumOxideSymmetricKey(sk) => Ok(EncryptingKey::SodiumOxideSymmetricKey(sk.build(bytes)?)),
        }
    }
}

impl Signer for SigningKey {
    fn sign(&self, bytes: ByteSource) -> Result<ByteSource, CryptoError> {
        match self {
            SigningKey::SodiumOxideEd25519(k) => {
                k.sign(bytes)
            },
            SigningKey::RingEd25519(k) => {
                k.sign(bytes)
            }
        }

    }
}

impl HasAlgorithmIdentifier for SigningKey {
    fn algorithm_identifier<'a>(&self) -> AlgorithmIdentifier<'a> {
        match self {
            SigningKey::SodiumOxideEd25519(k) => {
                k.algorithm_identifier()
            },
            SigningKey::RingEd25519(k) => {
                k.algorithm_identifier()
            }
        }
    }
}

impl HasByteSource for SigningKey {
    fn byte_source(&self) -> ByteSource {
        match self {
            SigningKey::SodiumOxideEd25519(k) => {
                k.byte_source()
            },
            SigningKey::RingEd25519(k) => {
                k.byte_source()
            }
        }
    }
}

impl HasPublicKey for SigningKey {
    type PublicKey = PublicAsymmetricKey;

    fn public_key(&self) -> Result<Self::PublicKey, CryptoError> {
        match self {
            SigningKey::SodiumOxideEd25519(k) =>
                Ok(PublicAsymmetricKey::SodiumOxideEd25519(k.public_key()?)),
            SigningKey::RingEd25519(k) =>
                Ok(PublicAsymmetricKey::RingEd25519(k.public_key()?))
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(tag = "t", content = "c")]
pub enum SecretAsymmetricKeyBuilder {
    SodiumOxideCurve25519(SodiumOxideCurve25519SecretAsymmetricKeyBuilder),
    SodiumOxideEd25519(SodiumOxideEd25519SecretAsymmetricKeyBuilder),
    RingEd25519(RingEd25519SecretAsymmetricKeyBuilder),
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
            SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(sosakb) => Ok(
                SecretAsymmetricKey::SodiumOxideCurve25519(sosakb.build(bytes)?),
            ),
            SecretAsymmetricKeyBuilder::SodiumOxideEd25519(sosakb) => Ok(
                SecretAsymmetricKey::SodiumOxideEd25519(sosakb.build(bytes)?),
            ),
            SecretAsymmetricKeyBuilder::RingEd25519(rsakb) => {
                Ok(SecretAsymmetricKey::RingEd25519(rsakb.build(bytes)?))
            }
        }
    }
}
