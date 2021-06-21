use crate::{
    Buildable, Builder, BytesSources, CryptoError, Name, States, Storer, TypeBuilder, Unsealer,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_::curve25519xsalsa20poly1305::{
        PublicKey as ExternalSodiumOxidePublicAsymmetricKey,
        SecretKey as ExternalSodiumOxideSecretAsymmetricKey,
        PUBLICKEYBYTES as EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES,
        SECRETKEYBYTES as EXTERNALSODIUMOXIDESECRETASYMMETRICKEYBYTES,
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
                unsealer: ref unsealable,
            } => {
                let bytes = unsealable.unseal(storer).await?;
                let builder = <SodiumOxideSymmetricKey as Buildable>::Builder::try_from(builder)?;
                builder.build(bytes.as_ref())?
            }
            States::Unsealed {
                ref builder,
                ref bytes,
            } => {
                let builder = <SodiumOxideSymmetricKey as Buildable>::Builder::try_from(builder)?;
                builder.build(bytes.as_ref())?
            }
        };

        let bytes = self.source.get()?;
        Ok(key.unseal(bytes.as_ref(), &self.nonce)?)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct SodiumOxideSymmetricKeyBuilder {}

impl TryFrom<TypeBuilder> for SodiumOxideSymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
            TypeBuilder::SodiumOxideSymmetricKey(soskb) => Ok(soskb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl TryFrom<&TypeBuilder> for SodiumOxideSymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: &TypeBuilder) -> Result<Self, Self::Error> {
        match builder {
            TypeBuilder::SodiumOxideSymmetricKey(soskb) => Ok(*soskb),
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

    fn builder() -> Self::Builder {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKeyReference {
    pub name: Name,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKey {
    pub key: ExternalSodiumOxideSecretAsymmetricKey,
}

impl SodiumOxideSecretAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDESECRETASYMMETRICKEYBYTES;
}

// PUBLIC ASYMMETRIC KEY \\

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicAsymmetricKeyReference {
    pub name: Name,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicAsymmetricKey {
    pub key: ExternalSodiumOxidePublicAsymmetricKey,
}

impl SodiumOxidePublicAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES;
}
