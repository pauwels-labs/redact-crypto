use crate::{
    AsymmetricKeyBuilder, Buildable, Builder, BytesSources, CryptoError, KeyBuilder, Name,
    PublicAsymmetricKeyBuilder, SecretAsymmetricKeyBuilder, States, Storer, SymmetricKeyBuilder,
    TypeBuilder, Unsealer,
};
use async_trait::async_trait;
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
pub struct SodiumOxideSymmetricKeyUnsealer {
    pub source: BytesSources,
    pub key: Box<States>,
    pub nonce: ExternalSodiumOxideSymmetricNonce,
}

#[async_trait]
impl Unsealer for SodiumOxideSymmetricKeyUnsealer {
    async fn unseal<T: Storer>(&self, storer: T) -> Result<Vec<u8>, CryptoError> {
        let key = match *self.key {
            States::Referenced { ref name } => {
                storer
                    .get::<SodiumOxideSymmetricKey>(&name)
                    .await
                    .map_err(|e| CryptoError::StorageError { source: e })?
            }
            States::Sealed {
                ref builder,
                ref unsealer,
            } => {
                let bytes = unsealer.unseal(storer).await?;
                let builder = <SodiumOxideSymmetricKey as Buildable>::Builder::try_from(*builder)?;
                builder.build(bytes.as_ref())?
            }
            States::Unsealed {
                ref builder,
                ref bytes,
            } => {
                let builder = <SodiumOxideSymmetricKey as Buildable>::Builder::try_from(*builder)?;
                builder.build(bytes.as_ref())?
            }
        };

        let bytes = self.source.get()?;
        Ok(key.unseal(bytes.as_ref(), &self.nonce)?)
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct SodiumOxideSymmetricKeyBuilder {}

impl TryFrom<TypeBuilder> for SodiumOxideSymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKey {
    pub key: ExternalSodiumOxideSymmetricKey,
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

// SECRET ASYMMETRIC KEY \\

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct SodiumOxideSecretAsymmetricKeyBuilder {}

impl TryFrom<TypeBuilder> for SodiumOxideSecretAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKey {
    pub key: ExternalSodiumOxideSecretAsymmetricKey,
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

impl TryFrom<TypeBuilder> for SodiumOxidePublicAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicAsymmetricKey {
    pub key: ExternalSodiumOxidePublicAsymmetricKey,
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
