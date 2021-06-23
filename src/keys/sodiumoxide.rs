use crate::{
    AsymmetricKeyBuilder, Buildable, Builder, ByteSealable, ByteUnsealable, BytesSources,
    CryptoError, IntoIndex, KeyBuilder, PublicAsymmetricKeyBuilder, Sealable,
    SecretAsymmetricKeyBuilder, States, Storer, SymmetricKeyBuilder, TypeBuilder,
    TypeBuilderContainer, Unsealable, VectorBytesSource,
};
use async_trait::async_trait;
use mongodb::bson::{self, Document};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_::{
        self,
        curve25519xsalsa20poly1305::{
            Nonce as ExternalSodiumOxideAsymmetricNonce,
            PublicKey as ExternalSodiumOxidePublicAsymmetricKey,
            SecretKey as ExternalSodiumOxideSecretAsymmetricKey,
            PUBLICKEYBYTES as EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES,
            SECRETKEYBYTES as EXTERNALSODIUMOXIDESECRETASYMMETRICKEYBYTES,
        },
    },
    secretbox::{
        self,
        xsalsa20poly1305::{
            Key as ExternalSodiumOxideSymmetricKey, Nonce as ExternalSodiumOxideSymmetricNonce,
            KEYBYTES as EXTERNALSODIUMOXIDESYMMETRICKEYBYTES,
        },
    },
};
use std::{boxed::Box, convert::TryFrom};

// SYMMETRIC KEY \\
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKeySealable {
    pub source: BytesSources,
    pub key: Box<States>,
    pub nonce: ExternalSodiumOxideSymmetricNonce,
}

#[async_trait]
impl Sealable for SodiumOxideSymmetricKeySealable {
    async fn seal<T: Storer>(self, storer: T) -> Result<ByteUnsealable, CryptoError> {
        let stateful_key = *self.key.clone();
        let key = storer.resolve::<SodiumOxideSymmetricKey>(*self.key).await?;
        let plaintext = self.source.get()?;
        let ciphertext = key.seal(plaintext, &self.nonce);
        Ok(ByteUnsealable::SodiumOxideSymmetricKey(
            SodiumOxideSymmetricKeyUnsealable {
                source: BytesSources::Vector(VectorBytesSource::new(Some(ciphertext.as_ref()))),
                key: Box::new(stateful_key),
                nonce: self.nonce,
            },
        ))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKeyUnsealable {
    pub source: BytesSources,
    pub key: Box<States>,
    pub nonce: ExternalSodiumOxideSymmetricNonce,
}

#[async_trait]
impl Unsealable for SodiumOxideSymmetricKeyUnsealable {
    async fn unseal<S: Storer>(self, storer: S) -> Result<ByteSealable, CryptoError> {
        let stateful_key = *self.key.clone();
        let key = storer.resolve::<SodiumOxideSymmetricKey>(*self.key).await?;
        let ciphertext = self.source.get()?;
        let plaintext = key.unseal(ciphertext, &self.nonce)?;
        Ok(ByteSealable::SodiumOxideSymmetricKey(
            SodiumOxideSymmetricKeySealable {
                source: BytesSources::Vector(VectorBytesSource::new(Some(plaintext.as_ref()))),
                key: Box::new(stateful_key),
                nonce: self.nonce,
            },
        ))
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct SodiumOxideSymmetricKeyBuilder {}

impl TryFrom<TypeBuilderContainer> for SodiumOxideSymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(soskb))) => {
                Ok(soskb)
            }
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for SodiumOxideSymmetricKeyBuilder {
    type Output = SodiumOxideSymmetricKey;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        Ok(SodiumOxideSymmetricKey {
            key: ExternalSodiumOxideSymmetricKey::from_slice(bytes).ok_or(
                CryptoError::InvalidKeyLength {
                    expected: SodiumOxideSymmetricKey::KEYBYTES,
                    actual: bytes.len(),
                },
            )?,
        })
    }
}

impl From<SodiumOxideSymmetricKeyBuilder> for TypeBuilder {
    fn from(b: SodiumOxideSymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(b)))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKey {
    pub key: ExternalSodiumOxideSymmetricKey,
}

impl IntoIndex for SodiumOxideSymmetricKey {
    fn into_index() -> Option<Document> {
        Some(bson::doc! {
        "c": {
            "builder": {
        "t": "Key",
        "c": {
            "t": "Symmetric",
        "c": {
        "t": "SodiumOxide"
        }
        }
            }
        }
            })
    }
}

impl Buildable for SodiumOxideSymmetricKey {
    type Builder = SodiumOxideSymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        SodiumOxideSymmetricKeyBuilder {}
    }
}

impl SodiumOxideSymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDESYMMETRICKEYBYTES;

    pub fn seal(&self, plaintext: &[u8], nonce: &ExternalSodiumOxideSymmetricNonce) -> Vec<u8> {
        secretbox::seal(plaintext, nonce, &self.key)
    }

    pub fn unseal(
        &self,
        ciphertext: &[u8],
        nonce: &ExternalSodiumOxideSymmetricNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        secretbox::open(ciphertext, nonce, &self.key)
            .map_err(|_| CryptoError::CiphertextFailedVerification)
    }
}

// impl Sealer for SodiumOxideSymmetricKey {
//     fn seal_unsealed(&self, source: BytesSources) -> Result<ByteUnsealable, CryptoError> {
//         let nonce = secretbox::gen_nonce();
//         let plaintext = source.get()?;
//         let ciphertext = self.seal(plaintext, &nonce);
//         Ok(ByteUnsealable::SodiumOxideSymmetricKey(
//             SodiumOxideSymmetricKeyUnsealable {
//                 source: BytesSources::Vector(VectorBytesSource::new(Some(ciphertext.as_ref()))),
//                 key: Box::new(States::Unsealed {
//                     builder: self.builder().into(),
//                     bytes: sodiumoxide::base64::encode(
//                         self.key.as_ref(),
//                         sodiumoxide::base64::Variant::Original,
//                     ),
//                 }),
//                 nonce,
//             },
//         ))
//     }

//     fn seal_ref(
//         &self,
//         source: BytesSources,
//         path: EntryPath,
//     ) -> Result<ByteUnsealable, CryptoError> {
//         let nonce = secretbox::gen_nonce();
//         let plaintext = source.get()?;
//         let ciphertext = self.seal(plaintext, &nonce);
//         Ok(ByteUnsealable::SodiumOxideSymmetricKey(
//             SodiumOxideSymmetricKeyUnsealable {
//                 source: BytesSources::Vector(VectorBytesSource::new(Some(ciphertext.as_ref()))),
//                 key: Box::new(States::Referenced {
//                     builder: self.builder().into(),
//                     path,
//                 }),
//                 nonce,
//             },
//         ))
//     }
// }

// SECRET ASYMMETRIC KEY \\

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct SodiumOxideSecretAsymmetricKeyBuilder {}

impl TryFrom<TypeBuilderContainer> for SodiumOxideSecretAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxide(sosakb),
            ))) => Ok(sosakb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for SodiumOxideSecretAsymmetricKeyBuilder {
    type Output = SodiumOxideSecretAsymmetricKey;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        Ok(SodiumOxideSecretAsymmetricKey {
            key: ExternalSodiumOxideSecretAsymmetricKey::from_slice(bytes).ok_or(
                CryptoError::InvalidKeyLength {
                    expected: SodiumOxideSecretAsymmetricKey::KEYBYTES,
                    actual: bytes.len(),
                },
            )?,
        })
    }
}

impl From<SodiumOxideSecretAsymmetricKeyBuilder> for TypeBuilder {
    fn from(b: SodiumOxideSecretAsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
            SecretAsymmetricKeyBuilder::SodiumOxide(b),
        )))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKey {
    pub key: ExternalSodiumOxideSecretAsymmetricKey,
}

impl IntoIndex for SodiumOxideSecretAsymmetricKey {
    fn into_index() -> Option<Document> {
        Some(bson::doc! {
        "c": {
            "builder": {
        "t": "Key",
        "c": {
            "t": "Asymmetric",
        "c": {
            "t": "Secret",
        "c": {
        "t": "SodiumOxide"
        }
        }
        }
            }
        }
            })
    }
}

impl Buildable for SodiumOxideSecretAsymmetricKey {
    type Builder = SodiumOxideSecretAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        SodiumOxideSecretAsymmetricKeyBuilder {}
    }
}

impl SodiumOxideSecretAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDESECRETASYMMETRICKEYBYTES;

    pub fn seal(
        &self,
        plaintext: &[u8],
        public_key: &ExternalSodiumOxidePublicAsymmetricKey,
        nonce: &ExternalSodiumOxideAsymmetricNonce,
    ) -> Vec<u8> {
        let precomputed_key = box_::precompute(public_key, &self.key);
        box_::seal_precomputed(plaintext, nonce, &precomputed_key)
    }

    pub fn unseal(
        &self,
        ciphertext: &[u8],
        public_key: &ExternalSodiumOxidePublicAsymmetricKey,
        nonce: &ExternalSodiumOxideAsymmetricNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        let precomputed_key = box_::precompute(public_key, &self.key);
        box_::open_precomputed(ciphertext, nonce, &precomputed_key)
            .map_err(|_| CryptoError::CiphertextFailedVerification)
    }
}

// PUBLIC ASYMMETRIC KEY \\

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct SodiumOxidePublicAsymmetricKeyBuilder {}

impl TryFrom<TypeBuilderContainer> for SodiumOxidePublicAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                PublicAsymmetricKeyBuilder::SodiumOxide(sopakb),
            ))) => Ok(sopakb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for SodiumOxidePublicAsymmetricKeyBuilder {
    type Output = SodiumOxidePublicAsymmetricKey;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        Ok(SodiumOxidePublicAsymmetricKey {
            key: ExternalSodiumOxidePublicAsymmetricKey::from_slice(bytes).ok_or(
                CryptoError::InvalidKeyLength {
                    expected: SodiumOxidePublicAsymmetricKey::KEYBYTES,
                    actual: bytes.len(),
                },
            )?,
        })
    }
}

impl From<SodiumOxidePublicAsymmetricKeyBuilder> for TypeBuilder {
    fn from(b: SodiumOxidePublicAsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
            PublicAsymmetricKeyBuilder::SodiumOxide(b),
        )))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicAsymmetricKey {
    pub key: ExternalSodiumOxidePublicAsymmetricKey,
}

impl IntoIndex for SodiumOxidePublicAsymmetricKey {
    fn into_index() -> Option<Document> {
        Some(bson::doc! {
        "c": {
            "builder": {
        "t": "Key",
        "c": {
            "t": "Asymmetric",
        "c": {
            "t": "Public",
        "c": {
        "t": "SodiumOxide"
        }
        }
        }
            }
        }
            })
    }
}

impl Buildable for SodiumOxidePublicAsymmetricKey {
    type Builder = SodiumOxidePublicAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        SodiumOxidePublicAsymmetricKeyBuilder {}
    }
}

impl SodiumOxidePublicAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES;

    pub fn seal(
        &self,
        plaintext: &[u8],
        secret_key: &ExternalSodiumOxideSecretAsymmetricKey,
        nonce: &ExternalSodiumOxideAsymmetricNonce,
    ) -> Vec<u8> {
        let precomputed_key = box_::precompute(&self.key, secret_key);
        box_::seal_precomputed(plaintext, nonce, &precomputed_key)
    }

    pub fn unseal(
        &self,
        ciphertext: &[u8],
        secret_key: &ExternalSodiumOxideSecretAsymmetricKey,
        nonce: &ExternalSodiumOxideAsymmetricNonce,
    ) -> Result<Vec<u8>, CryptoError> {
        let precomputed_key = box_::precompute(&self.key, secret_key);
        box_::open_precomputed(ciphertext, nonce, &precomputed_key)
            .map_err(|_| CryptoError::CiphertextFailedVerification)
    }
}
