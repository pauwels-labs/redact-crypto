use crate::{
    nonce::sodiumoxide::{SodiumOxideAsymmetricNonce, SodiumOxideSymmetricNonce},
    AsymmetricKeyBuilder, Builder, ByteSealable, ByteSource, ByteUnsealable, CryptoError,
    EntryPath, HasBuilder, HasIndex, KeyBuilder, PublicAsymmetricKeyBuilder,
    PublicAsymmetricSealer, PublicAsymmetricUnsealer, Sealable, SecretAsymmetricKeyBuilder,
    SecretAsymmetricSealer, SecretAsymmetricUnsealer, States, Storer, SymmetricKeyBuilder,
    SymmetricSealer, SymmetricUnsealer, TypeBuilder, TypeBuilderContainer, Unsealable,
    VectorByteSource,
};
use async_trait::async_trait;
use mongodb::bson::{self, Document};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_::{
        self,
        curve25519xsalsa20poly1305::{
            PublicKey as ExternalSodiumOxidePublicAsymmetricKey,
            SecretKey as ExternalSodiumOxideSecretAsymmetricKey,
            PUBLICKEYBYTES as EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES,
            SECRETKEYBYTES as EXTERNALSODIUMOXIDESECRETASYMMETRICKEYBYTES,
        },
    },
    secretbox::{
        self,
        xsalsa20poly1305::{
            Key as ExternalSodiumOxideSymmetricKey,
            KEYBYTES as EXTERNALSODIUMOXIDESYMMETRICKEYBYTES,
        },
    },
};
use std::{boxed::Box, convert::TryFrom};

// SYMMETRIC KEY \\
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKeySealable {
    pub source: ByteSource,
    pub key: Box<States>,
    pub nonce: SodiumOxideSymmetricNonce,
}

#[async_trait]
impl Sealable for SodiumOxideSymmetricKeySealable {
    async fn seal<T: Storer>(self, storer: T) -> Result<ByteUnsealable, CryptoError> {
        let stateful_key = *self.key.clone();
        let key = storer.resolve::<SodiumOxideSymmetricKey>(*self.key).await?;
        let mut unsealable = key.seal(self.source, Some(&self.nonce), None)?;
        unsealable.key = Box::new(stateful_key);
        Ok(ByteUnsealable::SodiumOxideSymmetricKey(unsealable))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKeyUnsealable {
    pub source: ByteSource,
    pub key: Box<States>,
    pub nonce: SodiumOxideSymmetricNonce,
}

#[async_trait]
impl Unsealable for SodiumOxideSymmetricKeyUnsealable {
    async fn unseal<S: Storer>(self, storer: S) -> Result<ByteSealable, CryptoError> {
        let path = match *self.key {
            States::Referenced {
                builder: _,
                ref path,
            } => Some(path.clone()),
            _ => None,
        };
        let key = storer.resolve::<SodiumOxideSymmetricKey>(*self.key).await?;
        let sosks = key.unseal(self.source, &self.nonce, path)?;
        Ok(ByteSealable::SodiumOxideSymmetricKey(sosks))
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
            key: ExternalSodiumOxideSymmetricKey::from_slice(&bytes).ok_or(
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

impl SymmetricSealer for SodiumOxideSymmetricKey {
    type SealedOutput = SodiumOxideSymmetricKeyUnsealable;
    type Nonce = SodiumOxideSymmetricNonce;

    fn seal(
        &self,
        plaintext: ByteSource,
        nonce: Option<&Self::Nonce>,
        key_path: Option<EntryPath>,
    ) -> Result<Self::SealedOutput, CryptoError> {
        let nonce = match nonce {
            Some(n) => n.clone(),
            None => SodiumOxideSymmetricNonce {
                nonce: secretbox::gen_nonce(),
            },
        };
        let plaintext = plaintext.get()?;
        let ciphertext = secretbox::seal(plaintext, &nonce.nonce, &self.key);
        let key = match key_path {
            Some(path) => Box::new(States::Referenced {
                builder: self.builder().into(),
                path,
            }),
            None => Box::new(States::Unsealed {
                builder: self.builder().into(),
                bytes: ByteSource::Vector(VectorByteSource::new(self.key.as_ref())),
            }),
        };
        Ok(SodiumOxideSymmetricKeyUnsealable {
            source: ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
            key,
            nonce,
        })
    }
}

impl SymmetricUnsealer for SodiumOxideSymmetricKey {
    type UnsealedOutput = SodiumOxideSymmetricKeySealable;
    type Nonce = SodiumOxideSymmetricNonce;

    fn unseal(
        &self,
        ciphertext: ByteSource,
        nonce: &Self::Nonce,
        key_path: Option<EntryPath>,
    ) -> Result<Self::UnsealedOutput, CryptoError> {
        let plaintext = secretbox::open(ciphertext.get()?, &nonce.nonce, &self.key)
            .map_err(|_| CryptoError::CiphertextFailedVerification)?;
        let key = match key_path {
            Some(path) => Box::new(States::Referenced {
                builder: self.builder().into(),
                path,
            }),
            None => Box::new(States::Unsealed {
                builder: self.builder().into(),
                bytes: ByteSource::Vector(VectorByteSource::new(self.key.as_ref())),
            }),
        };
        Ok(SodiumOxideSymmetricKeySealable {
            source: ByteSource::Vector(VectorByteSource::new(plaintext.as_ref())),
            key,
            nonce: nonce.clone(),
        })
    }
}

impl HasIndex for SodiumOxideSymmetricKey {
    type Index = Document;

    fn get_index() -> Option<Self::Index> {
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

impl HasBuilder for SodiumOxideSymmetricKey {
    type Builder = SodiumOxideSymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        SodiumOxideSymmetricKeyBuilder {}
    }
}

impl SodiumOxideSymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDESYMMETRICKEYBYTES;

    pub fn new() -> Self {
        SodiumOxideSymmetricKey {
            key: secretbox::gen_key(),
        }
    }
}

// SECRET ASYMMETRIC KEY \\
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKeySealable {
    pub source: ByteSource,
    pub secret_key: Box<States>,
    pub nonce: SodiumOxideAsymmetricNonce,
    pub public_key: Option<Box<States>>,
}

#[async_trait]
impl Sealable for SodiumOxideSecretAsymmetricKeySealable {
    async fn seal<T: Storer>(self, storer: T) -> Result<ByteUnsealable, CryptoError> {
        let stateful_secret_key = *self.secret_key.clone();
        let stateful_public_key = self.public_key.as_ref().cloned();
        let secret_key = storer
            .resolve::<SodiumOxideSecretAsymmetricKey>(*self.secret_key)
            .await?;
        let public_key = match self.public_key {
            Some(public_key) => Ok::<_, CryptoError>(Some(
                storer
                    .resolve::<SodiumOxidePublicAsymmetricKey>(*public_key)
                    .await?,
            )),
            None => Ok(None),
        }?;
        let mut unsealable =
            secret_key.seal(self.source, public_key.as_ref(), Some(&self.nonce), None)?;
        unsealable.secret_key = Box::new(stateful_secret_key);
        unsealable.public_key = stateful_public_key;
        Ok(ByteUnsealable::SodiumOxideSecretAsymmetricKey(unsealable))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKeyUnsealable {
    pub source: ByteSource,
    pub secret_key: Box<States>,
    pub nonce: SodiumOxideAsymmetricNonce,
    pub public_key: Option<Box<States>>,
}

#[async_trait]
impl Unsealable for SodiumOxideSecretAsymmetricKeyUnsealable {
    async fn unseal<S: Storer>(self, storer: S) -> Result<ByteSealable, CryptoError> {
        let stateful_secret_key = *self.secret_key.clone();
        let stateful_public_key = self.public_key.as_ref().cloned();
        let secret_key = storer
            .resolve::<SodiumOxideSecretAsymmetricKey>(*self.secret_key)
            .await?;
        let public_key = match self.public_key {
            Some(public_key) => Ok::<_, CryptoError>(Some(
                storer
                    .resolve::<SodiumOxidePublicAsymmetricKey>(*public_key)
                    .await?,
            )),
            None => Ok(None),
        }?;
        let mut sosaks = secret_key.unseal(self.source, public_key.as_ref(), &self.nonce, None)?;
        sosaks.secret_key = Box::new(stateful_secret_key);
        sosaks.public_key = stateful_public_key;
        Ok(ByteSealable::SodiumOxideSecretAsymmetricKey(sosaks))
    }
}

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
            secret_key: ExternalSodiumOxideSecretAsymmetricKey::from_slice(&bytes).ok_or(
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
    pub secret_key: ExternalSodiumOxideSecretAsymmetricKey,
}

impl SecretAsymmetricSealer for SodiumOxideSecretAsymmetricKey {
    type SealedOutput = SodiumOxideSecretAsymmetricKeyUnsealable;
    type Nonce = SodiumOxideAsymmetricNonce;
    type PublicKey = SodiumOxidePublicAsymmetricKey;

    fn seal(
        &self,
        plaintext: ByteSource,
        public_key: Option<&Self::PublicKey>,
        nonce: Option<&Self::Nonce>,
        key_path: Option<EntryPath>,
    ) -> Result<Self::SealedOutput, CryptoError> {
        let nonce = match nonce {
            Some(n) => n.clone(),
            None => SodiumOxideAsymmetricNonce {
                nonce: box_::gen_nonce(),
            },
        };
        let plaintext = plaintext.get()?;
        let public_key = match public_key {
            Some(sopak) => sopak.clone(),
            None => SodiumOxidePublicAsymmetricKey {
                public_key: self.secret_key.public_key(),
            },
        };
        let precomputed_key = box_::precompute(&public_key.public_key, &self.secret_key);
        let ciphertext = box_::seal_precomputed(plaintext, &nonce.nonce, &precomputed_key);
        let secret_key = match key_path {
            Some(path) => Box::new(States::Referenced {
                builder: self.builder().into(),
                path,
            }),
            None => Box::new(States::Unsealed {
                builder: self.builder().into(),
                bytes: ByteSource::Vector(VectorByteSource::new(self.secret_key.as_ref())),
            }),
        };
        let public_key = Box::new(States::Unsealed {
            builder: public_key.builder().into(),
            bytes: ByteSource::Vector(VectorByteSource::new(self.secret_key.as_ref())),
        });
        Ok(SodiumOxideSecretAsymmetricKeyUnsealable {
            source: ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
            secret_key,
            nonce,
            public_key: Some(public_key),
        })
    }
}

impl SecretAsymmetricUnsealer for SodiumOxideSecretAsymmetricKey {
    type UnsealedOutput = SodiumOxideSecretAsymmetricKeySealable;
    type Nonce = SodiumOxideAsymmetricNonce;
    type PublicKey = SodiumOxidePublicAsymmetricKey;

    fn unseal(
        &self,
        ciphertext: ByteSource,
        public_key: Option<&Self::PublicKey>,
        nonce: &Self::Nonce,
        key_path: Option<EntryPath>,
    ) -> Result<Self::UnsealedOutput, CryptoError> {
        let ciphertext = ciphertext.get()?;
        let public_key = match public_key {
            Some(sopak) => sopak.clone(),
            None => SodiumOxidePublicAsymmetricKey {
                public_key: self.secret_key.public_key(),
            },
        };
        let precomputed_key = box_::precompute(&public_key.public_key, &self.secret_key);
        let plaintext = box_::open_precomputed(ciphertext, &nonce.nonce, &precomputed_key)
            .map_err(|_| CryptoError::CiphertextFailedVerification)?;
        let secret_key = match key_path {
            Some(path) => Box::new(States::Referenced {
                builder: self.builder().into(),
                path,
            }),
            None => Box::new(States::Unsealed {
                builder: self.builder().into(),
                bytes: ByteSource::Vector(VectorByteSource::new(self.secret_key.as_ref())),
            }),
        };
        let public_key = Some(Box::new(States::Unsealed {
            builder: public_key.builder().into(),
            bytes: ByteSource::Vector(VectorByteSource::new(self.secret_key.as_ref())),
        }));
        Ok(SodiumOxideSecretAsymmetricKeySealable {
            source: ByteSource::Vector(VectorByteSource::new(plaintext.as_ref())),
            secret_key,
            nonce: nonce.clone(),
            public_key,
        })
    }
}

impl HasIndex for SodiumOxideSecretAsymmetricKey {
    type Index = Document;

    fn get_index() -> Option<Self::Index> {
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

impl HasBuilder for SodiumOxideSecretAsymmetricKey {
    type Builder = SodiumOxideSecretAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        SodiumOxideSecretAsymmetricKeyBuilder {}
    }
}

impl Default for SodiumOxideSecretAsymmetricKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SodiumOxideSecretAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDESECRETASYMMETRICKEYBYTES;

    pub fn new() -> Self {
        let (_, key) = box_::gen_keypair();
        SodiumOxideSecretAsymmetricKey { secret_key: key }
    }
}

// PUBLIC ASYMMETRIC KEY \\
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicAsymmetricKeySealable {
    pub source: ByteSource,
    pub public_key: Box<States>,
    pub nonce: SodiumOxideAsymmetricNonce,
    pub secret_key: Box<States>,
}

#[async_trait]
impl Sealable for SodiumOxidePublicAsymmetricKeySealable {
    async fn seal<T: Storer>(self, storer: T) -> Result<ByteUnsealable, CryptoError> {
        let stateful_secret_key = *self.secret_key.clone();
        let stateful_public_key = *self.public_key.clone();
        let secret_key_path = match *self.public_key {
            States::Referenced {
                builder: _,
                ref path,
            } => Some(path.clone()),
            _ => None,
        };
        let secret_key = storer
            .resolve::<SodiumOxideSecretAsymmetricKey>(*self.secret_key)
            .await?;
        let public_key = storer
            .resolve::<SodiumOxidePublicAsymmetricKey>(*self.public_key)
            .await?;
        let mut unsealable =
            public_key.seal(self.source, &secret_key, Some(&self.nonce), secret_key_path)?;
        unsealable.public_key = Box::new(stateful_public_key);
        unsealable.secret_key = Box::new(stateful_secret_key);
        Ok(ByteUnsealable::SodiumOxidePublicAsymmetricKey(unsealable))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicAsymmetricKeyUnsealable {
    pub source: ByteSource,
    pub public_key: Box<States>,
    pub nonce: SodiumOxideAsymmetricNonce,
    pub secret_key: Box<States>,
}

#[async_trait]
impl Unsealable for SodiumOxidePublicAsymmetricKeyUnsealable {
    async fn unseal<S: Storer>(self, storer: S) -> Result<ByteSealable, CryptoError> {
        let stateful_secret_key = *self.public_key.clone();
        let stateful_public_key = *self.public_key.clone();
        let secret_key = storer
            .resolve::<SodiumOxideSecretAsymmetricKey>(*self.secret_key)
            .await?;
        let public_key = storer
            .resolve::<SodiumOxidePublicAsymmetricKey>(*self.public_key)
            .await?;
        let mut sopaks = public_key.unseal(self.source, &secret_key, &self.nonce, None)?;
        sopaks.secret_key = Box::new(stateful_secret_key);
        sopaks.public_key = Box::new(stateful_public_key);
        Ok(ByteSealable::SodiumOxidePublicAsymmetricKey(sopaks))
    }
}

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
            public_key: ExternalSodiumOxidePublicAsymmetricKey::from_slice(&bytes).ok_or(
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
    pub public_key: ExternalSodiumOxidePublicAsymmetricKey,
}

impl PublicAsymmetricSealer for SodiumOxidePublicAsymmetricKey {
    type SealedOutput = SodiumOxidePublicAsymmetricKeyUnsealable;
    type Nonce = SodiumOxideAsymmetricNonce;
    type SecretKey = SodiumOxideSecretAsymmetricKey;

    fn seal(
        &self,
        plaintext: ByteSource,
        secret_key: &Self::SecretKey,
        nonce: Option<&Self::Nonce>,
        key_path: Option<EntryPath>,
    ) -> Result<Self::SealedOutput, CryptoError> {
        let nonce = match nonce {
            Some(n) => n.clone(),
            None => SodiumOxideAsymmetricNonce {
                nonce: box_::gen_nonce(),
            },
        };
        let plaintext = plaintext.get()?;
        let precomputed_key = box_::precompute(&self.public_key, &secret_key.secret_key);
        let ciphertext = box_::seal_precomputed(plaintext, &nonce.nonce, &precomputed_key);
        let secret_key = match key_path {
            Some(path) => Box::new(States::Referenced {
                builder: secret_key.builder().into(),
                path,
            }),
            None => Box::new(States::Unsealed {
                builder: secret_key.builder().into(),
                bytes: ByteSource::Vector(VectorByteSource::new(secret_key.secret_key.as_ref())),
            }),
        };
        let public_key = Box::new(States::Unsealed {
            builder: self.builder().into(),
            bytes: ByteSource::Vector(VectorByteSource::new(self.public_key.as_ref())),
        });
        Ok(SodiumOxidePublicAsymmetricKeyUnsealable {
            source: ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
            secret_key,
            nonce,
            public_key,
        })
    }
}

impl PublicAsymmetricUnsealer for SodiumOxidePublicAsymmetricKey {
    type UnsealedOutput = SodiumOxidePublicAsymmetricKeySealable;
    type Nonce = SodiumOxideAsymmetricNonce;
    type SecretKey = SodiumOxideSecretAsymmetricKey;

    fn unseal(
        &self,
        ciphertext: ByteSource,
        secret_key: &Self::SecretKey,
        nonce: &Self::Nonce,
        key_path: Option<EntryPath>,
    ) -> Result<Self::UnsealedOutput, CryptoError> {
        let ciphertext = ciphertext.get()?;
        let precomputed_key = box_::precompute(&self.public_key, &secret_key.secret_key);
        let plaintext = box_::open_precomputed(ciphertext, &nonce.nonce, &precomputed_key)
            .map_err(|_| CryptoError::CiphertextFailedVerification)?;
        let secret_key = match key_path {
            Some(path) => Box::new(States::Referenced {
                builder: secret_key.builder().into(),
                path,
            }),
            None => Box::new(States::Unsealed {
                builder: secret_key.builder().into(),
                bytes: ByteSource::Vector(VectorByteSource::new(secret_key.secret_key.as_ref())),
            }),
        };
        let public_key = Box::new(States::Unsealed {
            builder: self.builder().into(),
            bytes: ByteSource::Vector(VectorByteSource::new(self.public_key.as_ref())),
        });
        Ok(SodiumOxidePublicAsymmetricKeySealable {
            source: ByteSource::Vector(VectorByteSource::new(plaintext.as_ref())),
            public_key,
            nonce: nonce.clone(),
            secret_key,
        })
    }
}

impl HasIndex for SodiumOxidePublicAsymmetricKey {
    type Index = Document;

    fn get_index() -> Option<Self::Index> {
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

impl HasBuilder for SodiumOxidePublicAsymmetricKey {
    type Builder = SodiumOxidePublicAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        SodiumOxidePublicAsymmetricKeyBuilder {}
    }
}

impl SodiumOxidePublicAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES;

    pub fn new() -> (Self, SodiumOxideSecretAsymmetricKey) {
        let (public_key, secret_key) = box_::gen_keypair();
        (
            SodiumOxidePublicAsymmetricKey { public_key },
            SodiumOxideSecretAsymmetricKey { secret_key },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SodiumOxidePublicAsymmetricKey, SodiumOxidePublicAsymmetricKeyBuilder,
        SodiumOxidePublicAsymmetricKeySealable, SodiumOxidePublicAsymmetricKeyUnsealable,
        SodiumOxideSecretAsymmetricKey, SodiumOxideSecretAsymmetricKeyBuilder,
        SodiumOxideSecretAsymmetricKeySealable, SodiumOxideSecretAsymmetricKeyUnsealable,
        SodiumOxideSymmetricKey, SodiumOxideSymmetricKeyBuilder, SodiumOxideSymmetricKeySealable,
        SodiumOxideSymmetricKeyUnsealable,
    };
    use crate::{
        nonce::sodiumoxide::{SodiumOxideAsymmetricNonce, SodiumOxideSymmetricNonce},
        storage::tests::MockStorer,
        AsymmetricKeyBuilder, BoolDataBuilder, Builder, ByteSource, ByteUnsealable, DataBuilder,
        Entry, HasBuilder, HasIndex, KeyBuilder, PublicAsymmetricKeyBuilder,
        PublicAsymmetricSealer, PublicAsymmetricUnsealer, Sealable, SecretAsymmetricKeyBuilder,
        SecretAsymmetricSealer, SecretAsymmetricUnsealer, States, StringDataBuilder,
        SymmetricKeyBuilder, SymmetricSealer, SymmetricUnsealer, TypeBuilder, TypeBuilderContainer,
        Unsealable, VectorByteSource,
    };
    use mongodb::bson::{self, Document};
    use sodiumoxide::crypto::{
        box_,
        secretbox::{self, xsalsa20poly1305::Nonce as ExternalSodiumOxideSymmetricNonce},
    };
    use std::convert::TryInto;

    //////////////////////////////////////////////
    /// PUBLIC ASYMMETRIC KEY HELPER FUNCTIONS ///
    //////////////////////////////////////////////
    fn get_sopak_ciphertext(
        plaintext: &[u8],
        secret_key: Option<&SodiumOxideSecretAsymmetricKey>,
    ) -> Vec<u8> {
        let secret_key = match secret_key {
            Some(sk) => sk.clone(),
            None => get_sosak(),
        };
        let (public_key, _) = get_sopak();
        let nonce = get_soan();
        let precomputed_key = box_::precompute(&public_key.public_key, &secret_key.secret_key);
        box_::seal_precomputed(plaintext, &nonce.nonce, &precomputed_key)
    }

    fn get_sopak() -> (
        SodiumOxidePublicAsymmetricKey,
        SodiumOxideSecretAsymmetricKey,
    ) {
        let key_bytes: [u8; 32] = [
            77, 166, 178, 227, 216, 254, 219, 202, 41, 198, 74, 141, 126, 196, 68, 179, 19, 218,
            34, 107, 174, 121, 199, 180, 254, 254, 161, 219, 225, 158, 220, 56,
        ];
        let sosakb = SodiumOxideSecretAsymmetricKeyBuilder {};
        let secret_key = sosakb.build(&key_bytes).unwrap();
        let public_key = SodiumOxidePublicAsymmetricKey {
            public_key: secret_key.secret_key.public_key(),
        };

        (public_key, secret_key)
    }

    fn get_unsealed_sopak() -> States {
        let (public_key, _) = get_sopak();
        States::Unsealed {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                PublicAsymmetricKeyBuilder::SodiumOxide(public_key.builder()),
            ))),
            bytes: ByteSource::Vector(VectorByteSource::new(public_key.public_key.as_ref())),
        }
    }

    fn get_referenced_sopak(path: &str) -> States {
        States::Referenced {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                PublicAsymmetricKeyBuilder::SodiumOxide(SodiumOxidePublicAsymmetricKeyBuilder {}),
            ))),
            path: path.to_owned(),
        }
    }

    // fn get_sealed_sopak_with_unsealed_key() -> States {
    //     let (public_key, secret_key) = get_sopak();
    //     States::Sealed {
    //         builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
    //             PublicAsymmetricKeyBuilder::SodiumOxide(SodiumOxidePublicAsymmetricKeyBuilder {}),
    //         ))),
    //         unsealable: ByteUnsealable::SodiumOxidePublicAsymmetricKey(
    //             get_sopaku_with_unsealed_key(public_key.public_key_key.as_ref(), None),
    //         ),
    //     }
    // }

    // fn get_sealed_sopak_with_referenced_key(path: &str) -> States {
    //     States::Sealed {
    //         builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
    //             SecretAsymmetricKeyBuilder::SodiumOxide(SodiumOxideSecretAsymmetricKeyBuilder {}),
    //         ))),
    //         unsealable: ByteUnsealable::SodiumOxideSecretAsymmetricKey(
    //             get_sopaku_with_referenced_key(get_sopak().secret_key.as_ref(), None, path),
    //         ),
    //     }
    // }

    fn get_sopaks_with_unsealed_key(
        payload: &[u8],
        secret_key: Option<&SodiumOxideSecretAsymmetricKey>,
    ) -> SodiumOxidePublicAsymmetricKeySealable {
        let source = ByteSource::Vector(VectorByteSource::new(payload));
        let secret_key = match secret_key {
            Some(sk) => Box::new(States::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                    SecretAsymmetricKeyBuilder::SodiumOxide(sk.builder()),
                ))),
                bytes: ByteSource::Vector(VectorByteSource::new(sk.secret_key.as_ref())),
            }),
            None => Box::new(get_unsealed_sosak()),
        };

        SodiumOxidePublicAsymmetricKeySealable {
            source,
            public_key: Box::new(get_unsealed_sopak()),
            nonce: get_soan(),
            secret_key,
        }
    }

    fn get_sopaks_with_referenced_key(
        payload: &[u8],
        secret_key: Option<&SodiumOxideSecretAsymmetricKey>,
        path: &str,
    ) -> SodiumOxidePublicAsymmetricKeySealable {
        let source = ByteSource::Vector(VectorByteSource::new(payload));
        let secret_key = match secret_key {
            Some(sk) => Box::new(States::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                    SecretAsymmetricKeyBuilder::SodiumOxide(sk.builder()),
                ))),
                bytes: ByteSource::Vector(VectorByteSource::new(sk.secret_key.as_ref())),
            }),
            None => Box::new(get_unsealed_sosak()),
        };
        SodiumOxidePublicAsymmetricKeySealable {
            source,
            secret_key,
            nonce: get_soan(),
            public_key: Box::new(get_referenced_sopak(path)),
        }
    }

    fn get_sopaku_with_unsealed_key(
        plaintext: &[u8],
        secret_key: Option<&SodiumOxideSecretAsymmetricKey>,
    ) -> SodiumOxidePublicAsymmetricKeyUnsealable {
        let ciphertext = get_sopak_ciphertext(plaintext, secret_key);
        let secret_key = match secret_key {
            Some(sk) => Box::new(States::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                    SecretAsymmetricKeyBuilder::SodiumOxide(
                        SodiumOxideSecretAsymmetricKeyBuilder {},
                    ),
                ))),
                bytes: ByteSource::Vector(VectorByteSource::new(sk.secret_key.as_ref())),
            }),
            None => Box::new(get_unsealed_sosak()),
        };
        let source = ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref()));
        SodiumOxidePublicAsymmetricKeyUnsealable {
            source,
            secret_key,
            nonce: get_soan(),
            public_key: Box::new(get_unsealed_sopak()),
        }
    }

    fn get_sopaku_with_referenced_key(
        plaintext: &[u8],
        secret_key: Option<&SodiumOxideSecretAsymmetricKey>,
        path: &str,
    ) -> SodiumOxidePublicAsymmetricKeyUnsealable {
        let ciphertext = get_sopak_ciphertext(plaintext, secret_key);
        let secret_key = match secret_key {
            Some(sk) => Box::new(States::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                    SecretAsymmetricKeyBuilder::SodiumOxide(
                        SodiumOxideSecretAsymmetricKeyBuilder {},
                    ),
                ))),
                bytes: ByteSource::Vector(VectorByteSource::new(sk.secret_key.as_ref())),
            }),
            None => Box::new(get_unsealed_sosak()),
        };
        let source = ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref()));
        SodiumOxidePublicAsymmetricKeyUnsealable {
            source,
            secret_key,
            nonce: get_soan(),
            public_key: Box::new(get_referenced_sopak(path)),
        }
    }

    //////////////////////////////////////////////
    /// SECRET ASYMMETRIC KEY HELPER FUNCTIONS ///
    //////////////////////////////////////////////
    fn get_sosak_ciphertext(
        plaintext: &[u8],
        public_key: Option<SodiumOxidePublicAsymmetricKey>,
    ) -> Vec<u8> {
        let key = get_sosak();
        let nonce = get_soan();
        let public_key = match public_key {
            Some(k) => k,
            None => SodiumOxidePublicAsymmetricKey {
                public_key: key.secret_key.public_key(),
            },
        };
        let precomputed_key = box_::precompute(&public_key.public_key, &key.secret_key);
        box_::seal_precomputed(plaintext, &nonce.nonce, &precomputed_key)
    }

    fn get_sosak() -> SodiumOxideSecretAsymmetricKey {
        let key_bytes: [u8; 32] = [
            77, 166, 178, 227, 216, 254, 219, 202, 41, 198, 74, 141, 126, 196, 68, 179, 19, 218,
            34, 107, 174, 121, 199, 180, 254, 254, 161, 219, 225, 158, 220, 56,
        ];
        let sosakb = SodiumOxideSecretAsymmetricKeyBuilder {};
        sosakb.build(&key_bytes).unwrap()
    }

    fn get_soan() -> SodiumOxideAsymmetricNonce {
        let nonce_bytes: [u8; 24] = [
            24, 101, 189, 110, 189, 19, 129, 254, 163, 80, 137, 144, 100, 21, 11, 191, 22, 47, 64,
            132, 80, 122, 1, 237,
        ];
        let nonce = box_::curve25519xsalsa20poly1305::Nonce::from_slice(&nonce_bytes).unwrap();
        SodiumOxideAsymmetricNonce { nonce }
    }

    fn get_unsealed_sosak() -> States {
        let key = get_sosak();
        States::Unsealed {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxide(key.builder()),
            ))),
            bytes: ByteSource::Vector(VectorByteSource::new(key.secret_key.as_ref())),
        }
    }

    fn get_referenced_sosak(path: &str) -> States {
        States::Referenced {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxide(SodiumOxideSecretAsymmetricKeyBuilder {}),
            ))),
            path: path.to_owned(),
        }
    }

    fn get_sealed_sosak_with_unsealed_key() -> States {
        States::Sealed {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxide(SodiumOxideSecretAsymmetricKeyBuilder {}),
            ))),
            unsealable: ByteUnsealable::SodiumOxideSecretAsymmetricKey(
                get_sosaku_with_unsealed_key(get_sosak().secret_key.as_ref(), None),
            ),
        }
    }

    fn get_sealed_sosak_with_referenced_key(path: &str) -> States {
        States::Sealed {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxide(SodiumOxideSecretAsymmetricKeyBuilder {}),
            ))),
            unsealable: ByteUnsealable::SodiumOxideSecretAsymmetricKey(
                get_sosaku_with_referenced_key(get_sosak().secret_key.as_ref(), None, path),
            ),
        }
    }

    fn get_sosaks_with_unsealed_key(
        payload: &[u8],
        public_key: Option<SodiumOxidePublicAsymmetricKey>,
    ) -> SodiumOxideSecretAsymmetricKeySealable {
        let source = ByteSource::Vector(VectorByteSource::new(payload));
        let public_key = match public_key {
            Some(pk) => Some(Box::new(States::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                    PublicAsymmetricKeyBuilder::SodiumOxide(
                        SodiumOxidePublicAsymmetricKeyBuilder {},
                    ),
                ))),
                bytes: ByteSource::Vector(VectorByteSource::new(pk.public_key.as_ref())),
            })),
            None => None,
        };
        SodiumOxideSecretAsymmetricKeySealable {
            source,
            secret_key: Box::new(get_unsealed_sosak()),
            nonce: get_soan(),
            public_key,
        }
    }

    fn get_sosaks_with_referenced_key(
        payload: &[u8],
        public_key: Option<SodiumOxidePublicAsymmetricKey>,
        path: &str,
    ) -> SodiumOxideSecretAsymmetricKeySealable {
        let source = ByteSource::Vector(VectorByteSource::new(payload));
        let public_key = match public_key {
            Some(pk) => Some(Box::new(States::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                    PublicAsymmetricKeyBuilder::SodiumOxide(
                        SodiumOxidePublicAsymmetricKeyBuilder {},
                    ),
                ))),
                bytes: ByteSource::Vector(VectorByteSource::new(pk.public_key.as_ref())),
            })),
            None => None,
        };
        SodiumOxideSecretAsymmetricKeySealable {
            source,
            secret_key: Box::new(get_referenced_sosak(path)),
            nonce: get_soan(),
            public_key,
        }
    }

    fn get_sosaku_with_unsealed_key(
        plaintext: &[u8],
        public_key: Option<SodiumOxidePublicAsymmetricKey>,
    ) -> SodiumOxideSecretAsymmetricKeyUnsealable {
        let ciphertext = get_sosak_ciphertext(plaintext, public_key.clone());
        let public_key = match public_key {
            Some(pk) => Some(Box::new(States::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                    PublicAsymmetricKeyBuilder::SodiumOxide(
                        SodiumOxidePublicAsymmetricKeyBuilder {},
                    ),
                ))),
                bytes: ByteSource::Vector(VectorByteSource::new(pk.public_key.as_ref())),
            })),
            None => None,
        };
        let source = ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref()));
        SodiumOxideSecretAsymmetricKeyUnsealable {
            source,
            secret_key: Box::new(get_unsealed_sosak()),
            nonce: get_soan(),
            public_key,
        }
    }

    fn get_sosaku_with_referenced_key(
        plaintext: &[u8],
        public_key: Option<SodiumOxidePublicAsymmetricKey>,
        path: &str,
    ) -> SodiumOxideSecretAsymmetricKeyUnsealable {
        let ciphertext = get_sosak_ciphertext(plaintext, public_key.clone());
        let public_key = match public_key {
            Some(pk) => Some(Box::new(States::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                    PublicAsymmetricKeyBuilder::SodiumOxide(
                        SodiumOxidePublicAsymmetricKeyBuilder {},
                    ),
                ))),
                bytes: ByteSource::Vector(VectorByteSource::new(pk.public_key.as_ref())),
            })),
            None => None,
        };
        let source = ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref()));
        SodiumOxideSecretAsymmetricKeyUnsealable {
            source,
            secret_key: Box::new(get_referenced_sosak(path)),
            nonce: get_soan(),
            public_key,
        }
    }

    //////////////////////////////////////
    /// SYMMETRIC KEY HELPER FUNCTIONS ///
    //////////////////////////////////////
    /// Returns the ciphertext for the given text using the key from get_sosk()
    /// and the nonce from get_sosn()
    fn get_sosk_ciphertext(plaintext: &[u8]) -> Vec<u8> {
        let key = get_sosk();
        let nonce = get_sosn();
        secretbox::seal(plaintext, &nonce.nonce, &key.key)
    }

    /// Returns the exact same symmetric key on every call
    fn get_sosk() -> SodiumOxideSymmetricKey {
        let key_bytes: [u8; 32] = [
            188, 223, 72, 202, 66, 168, 65, 178, 120, 109, 80, 156, 14, 16, 212, 28, 77, 40, 207,
            216, 211, 141, 66, 62, 17, 156, 76, 160, 132, 29, 145, 18,
        ];
        let soskb = SodiumOxideSymmetricKeyBuilder {};
        soskb.build(&key_bytes).unwrap()
    }

    /// Returns the exact same symmetric nonce on every call
    fn get_sosn() -> SodiumOxideSymmetricNonce {
        let nonce_bytes: [u8; 24] = [
            13, 7, 8, 143, 25, 5, 250, 134, 70, 171, 199, 182, 68, 69, 45, 89, 178, 90, 14, 31,
            220, 196, 79, 116,
        ];
        SodiumOxideSymmetricNonce {
            nonce: ExternalSodiumOxideSymmetricNonce::from_slice(&nonce_bytes).unwrap(),
        }
    }

    /// Returns the key from get_sosk() wrapped in a States::Unsealed
    fn get_unsealed_sosk() -> States {
        let sosk = get_sosk();
        States::Unsealed {
            builder: TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(
                sosk.builder(),
            ))),
            bytes: ByteSource::Vector(VectorByteSource::new(sosk.key.as_ref())),
        }
    }

    /// Returns the key from get_sosk() wrapped in a States::Referenced
    fn get_referenced_sosk(path: &str) -> States {
        States::Referenced {
            builder: TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(
                SodiumOxideSymmetricKeyBuilder {},
            ))),
            path: path.to_string(),
        }
    }

    /// Returns the key from get_sosk() wrapped in a States::Sealed and decrypted
    /// by an unsealed version of the key from get_sosk()
    fn get_sealed_sosk_with_unsealed_key() -> States {
        States::Sealed {
            builder: TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(
                SodiumOxideSymmetricKeyBuilder {},
            ))),
            unsealable: ByteUnsealable::SodiumOxideSymmetricKey(get_sosku_with_unsealed_key(
                get_sosk().key.as_ref(),
            )),
        }
    }

    /// Returns the key from get_sosk() wrapped in a States::Sealed and decrypted
    /// by a States::Referenced with the given path
    fn get_sealed_sosk_with_referenced_key(path: &str) -> States {
        States::Sealed {
            builder: TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(
                SodiumOxideSymmetricKeyBuilder {},
            ))),
            unsealable: ByteUnsealable::SodiumOxideSymmetricKey(get_sosku_with_referenced_key(
                get_sosk().key.as_ref(),
                path,
            )),
        }
    }

    /// Returns a sealable backed by get_unsealed_sosk() with the bytes "hello, world!"
    fn get_sosks_with_unsealed_key(payload: &[u8]) -> SodiumOxideSymmetricKeySealable {
        let source = ByteSource::Vector(VectorByteSource::new(payload));
        SodiumOxideSymmetricKeySealable {
            source,
            key: Box::new(get_unsealed_sosk()),
            nonce: get_sosn(),
        }
    }

    /// Returns a sealable backed by get_referenced_sosk() with the bytes "hello, world!"
    fn get_sosks_with_referenced_key(
        payload: &[u8],
        path: &str,
    ) -> SodiumOxideSymmetricKeySealable {
        let source = ByteSource::Vector(VectorByteSource::new(payload));
        SodiumOxideSymmetricKeySealable {
            source,
            key: Box::new(get_referenced_sosk(path)),
            nonce: get_sosn(),
        }
    }

    fn get_sosku_with_unsealed_key(plaintext: &[u8]) -> SodiumOxideSymmetricKeyUnsealable {
        let sealed_bytes = get_sosk_ciphertext(plaintext);
        let source = ByteSource::Vector(VectorByteSource::new(sealed_bytes.as_ref()));
        SodiumOxideSymmetricKeyUnsealable {
            source,
            key: Box::new(get_unsealed_sosk()),
            nonce: get_sosn(),
        }
    }

    fn get_sosku_with_referenced_key(
        plaintext: &[u8],
        path: &str,
    ) -> SodiumOxideSymmetricKeyUnsealable {
        let sealed_bytes = get_sosk_ciphertext(plaintext);
        let source = ByteSource::Vector(VectorByteSource::new(sealed_bytes.as_ref()));
        SodiumOxideSymmetricKeyUnsealable {
            source,
            key: Box::new(get_referenced_sosk(path)),
            nonce: get_sosn(),
        }
    }

    #[tokio::test]
    async fn test_seal_symmetrickeysealable_with_unsealed_key() {
        let sosks = get_sosks_with_unsealed_key(b"hello, world");
        let storer = MockStorer::new();
        let _ = sosks.seal(storer).await.unwrap();
    }

    #[tokio::test]
    async fn test_seal_symmetrickeysealable_with_referenced_key() {
        let sosks = get_sosks_with_referenced_key(b"hello, world", ".path.default.");
        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SodiumOxideSymmetricKey>()
            .withf(|path: &str, index: &Option<Document>| {
                path == ".path.default." && *index == Some(bson::doc! { "c": { "builder": { "t": "Key", "c": { "t": "Symmetric", "c": { "t": "SodiumOxide" } } } } })
            })
            .returning(|path, _| {
                Ok(Entry {
                    path: path.to_owned(),
                    value: get_unsealed_sosk(),
                })
            });
        let _ = sosks.seal(storer).await.unwrap();
    }

    #[tokio::test]
    async fn test_unseal_symmetrickeyunsealable_with_unsealed_key() {
        let sosku = get_sosku_with_unsealed_key(b"hello, world!");
        let storer = MockStorer::new();
        let bs = sosku.unseal(storer).await.unwrap();
        let source = bs.get_source();
        let sdb = StringDataBuilder {};
        let d = sdb.build(source.get().unwrap()).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

    #[tokio::test]
    async fn test_unseal_symmetrickeyunsealable_with_referenced_key() {
        let sosku = get_sosku_with_referenced_key(b"hello, world!", ".keys.default.");
        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SodiumOxideSymmetricKey>()
            .withf(|path: &str, index: &Option<Document>| {
                path == ".keys.default." && *index == Some(bson::doc! { "c": { "builder": { "t": "Key", "c": { "t": "Symmetric", "c": { "t": "SodiumOxide" } } } } })
            })
            .returning(move |path, _| {
                Ok(Entry {
                    path: path.to_owned(),
                    value: get_unsealed_sosk(),
                })
            });
        let bs = sosku.unseal(storer).await.unwrap();
        let source = bs.get_source();
        let sdb = StringDataBuilder {};
        let d = sdb.build(source.get().unwrap()).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

    #[test]
    fn test_sodiumoxidesymmetrickeybuilder_build_valid() {
        let soskb = SodiumOxideSymmetricKeyBuilder {};
        let external_key = secretbox::gen_key();
        let key = soskb.build(external_key.as_ref()).unwrap();
        assert_eq!(key.key.as_ref(), external_key.as_ref());
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidesymmetrickeybuilder_build_invalid() {
        let soskb = SodiumOxideSymmetricKeyBuilder {};
        let _ = soskb.build(b"bla").unwrap();
    }

    #[test]
    fn test_sodiumoxidesymmetrickeybuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Symmetric(
            SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
        )));
        let soskb: SodiumOxideSymmetricKeyBuilder = tbc.try_into().unwrap();
        let key = SodiumOxideSymmetricKey::new();
        soskb.build(key.key.as_ref()).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidesymmetrickeybuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {})));
        let _: SodiumOxideSymmetricKeyBuilder = tbc.try_into().unwrap();
    }

    #[test]
    fn test_seal_symmetrickey_with_non_referenced_key() {
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let sosk = get_sosk();
        let unsealable = sosk.seal(plaintext, Some(&get_sosn()), None).unwrap();
        match *unsealable.key {
            States::Unsealed {
                builder: _,
                bytes: _,
            } => (),
            _ => panic!("Key used for unsealable should have been unsealed"),
        };
        assert_eq!(
            get_sosk_ciphertext(b"hello, world!"),
            unsealable.source.get().unwrap().to_vec(),
        );
    }

    #[test]
    fn test_seal_symmetrickey_with_referenced_key() {
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let sosk = get_sosk();
        let unsealable = sosk
            .seal(
                plaintext,
                Some(&get_sosn()),
                Some(".keys.somePath.".to_owned()),
            )
            .unwrap();
        match *unsealable.key {
            States::Referenced { builder: _, path } => {
                assert_eq!(path, ".keys.somePath.".to_owned())
            }
            _ => panic!("Key used for unsealable should have been unsealed"),
        };
        assert_eq!(
            get_sosk_ciphertext(b"hello, world!"),
            unsealable.source.get().unwrap().to_vec(),
        );
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_symmetrickey_unseal_with_invalid_bytes() {
        let sosk = get_sosk();
        let ciphertext = ByteSource::Vector(VectorByteSource::new(b"bla"));
        let _ = sosk.unseal(ciphertext, &get_sosn(), None).unwrap();
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_symmetrickey_unseal_with_invalid_nonce() {
        let sosk = get_sosk();
        let ciphertext = get_sosk_ciphertext(b"hello, world!");
        let _ = sosk
            .unseal(
                ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
                &SodiumOxideSymmetricNonce {
                    nonce: secretbox::gen_nonce(),
                },
                None,
            )
            .unwrap();
    }

    #[test]
    fn test_symmetrickey_to_index() {
        let index = SodiumOxideSymmetricKey::get_index();
        assert_eq!(
            index,
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
        )
    }

    #[test]
    fn test_symmetrickey_to_builder() {
        let sosk = SodiumOxideSymmetricKey::new();
        let builder = sosk.builder();
        let key_bytes = sosk.key.as_ref();
        let built_key = builder.build(key_bytes).unwrap();
        assert_eq!(built_key.key.as_ref(), sosk.key.as_ref());
    }

    #[test]
    fn test_symmetrickey_new() {
        let sosk = SodiumOxideSymmetricKey::new();
        assert!(!sosk.key.as_ref().is_empty());
    }

    ///////////////////////////////////
    /// SECRET ASYMMETRIC KEY TESTS ///
    ///////////////////////////////////

    #[tokio::test]
    async fn test_seal_secretasymmetrickeysealable_with_unsealed_key() {
        let sosaks = get_sosaks_with_unsealed_key(b"hello, world!", None);
        let storer = MockStorer::new();
        let ciphertext = sosaks.seal(storer).await.unwrap();
        assert_eq!(
            ciphertext.get_source().get().unwrap(),
            get_sosak_ciphertext(b"hello, world!", None)
        );
    }

    #[tokio::test]
    async fn test_seal_secretasymmetrickeysealable_with_separate_public_key() {
        let (other_sopak, _) = SodiumOxidePublicAsymmetricKey::new();
        let sosaks = get_sosaks_with_unsealed_key(b"hello, world!", Some(other_sopak.clone()));
        let storer = MockStorer::new();
        let ciphertext = sosaks.seal(storer).await.unwrap();
        assert_eq!(
            ciphertext.get_source().get().unwrap(),
            get_sosak_ciphertext(b"hello, world!", Some(other_sopak))
        );
    }

    #[tokio::test]
    async fn test_seal_secretasymmetrickeysealable_with_referenced_key() {
        let sosaks = get_sosaks_with_referenced_key(b"hello, world!", None, ".keys.default.");
        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SodiumOxideSecretAsymmetricKey>()
            .withf(|path: &str, index: &Option<Document>| {
                path == ".keys.default." && *index == SodiumOxideSecretAsymmetricKey::get_index()
            })
            .returning(|path, _| {
                Ok(Entry {
                    path: path.to_owned(),
                    value: get_unsealed_sosak(),
                })
            });
        let ciphertext = sosaks.seal(storer).await.unwrap();
        assert_eq!(
            ciphertext.get_source().get().unwrap(),
            get_sosak_ciphertext(b"hello, world!", None)
        );
    }

    #[tokio::test]
    async fn test_unseal_secretasymmetrickeyunsealable_with_unsealed_key() {
        let sosaku = get_sosaku_with_unsealed_key(b"hello, world!", None);
        let storer = MockStorer::new();
        let bs = sosaku.unseal(storer).await.unwrap();
        let source = bs.get_source();
        let sdb = StringDataBuilder {};
        let d = sdb.build(source.get().unwrap()).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

    #[tokio::test]
    async fn test_unseal_secretasymmetrickeyunsealable_with_separate_public_key() {
        let (other_sopak, _) = SodiumOxidePublicAsymmetricKey::new();
        let sosaku = get_sosaku_with_unsealed_key(b"hello, world!", Some(other_sopak.clone()));
        let storer = MockStorer::new();
        let ciphertext = sosaku.unseal(storer).await.unwrap();
        assert_eq!(ciphertext.get_source().get().unwrap(), b"hello, world!",);
    }

    #[tokio::test]
    async fn test_unseal_secretasymmetrickeyunsealable_with_referenced_key() {
        let sosaku = get_sosaku_with_referenced_key(b"hello, world!", None, ".keys.default.");
        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SodiumOxideSecretAsymmetricKey>()
            .withf(|path: &str, index: &Option<Document>| {
                path == ".keys.default." && *index == SodiumOxideSecretAsymmetricKey::get_index()
            })
            .returning(|path, _| {
                Ok(Entry {
                    path: path.to_owned(),
                    value: get_unsealed_sosak(),
                })
            });
        let bs = sosaku.unseal(storer).await.unwrap();
        let source = bs.get_source();
        let sdb = StringDataBuilder {};
        let d = sdb.build(source.get().unwrap()).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

    #[test]
    fn test_sodiumoxidesecretasymmetrickeybuilder_build_valid() {
        let sosakb = SodiumOxideSecretAsymmetricKeyBuilder {};
        let (_, sk) = box_::gen_keypair();
        let key = sosakb.build(sk.as_ref()).unwrap();
        assert_eq!(key.secret_key.as_ref(), sk.as_ref());
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidesecretasymmetrickeybuilder_build_invalid() {
        let sosakb = SodiumOxideSecretAsymmetricKeyBuilder {};
        let _ = sosakb.build(b"bla").unwrap();
    }

    #[test]
    fn test_sodiumoxidesecretasymmetrickeybuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Asymmetric(
            AsymmetricKeyBuilder::Secret(SecretAsymmetricKeyBuilder::SodiumOxide(
                SodiumOxideSecretAsymmetricKeyBuilder {},
            )),
        )));
        let sosakb: SodiumOxideSecretAsymmetricKeyBuilder = tbc.try_into().unwrap();
        let key = SodiumOxideSecretAsymmetricKey::new();
        sosakb.build(key.secret_key.as_ref()).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidesecretasymmetrickeybuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {})));
        let _: SodiumOxideSecretAsymmetricKeyBuilder = tbc.try_into().unwrap();
    }

    #[test]
    fn test_seal_secretasymmetrickey_with_non_referenced_key() {
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let sosak = get_sosak();
        let unsealable = sosak
            .seal(plaintext, None, Some(&get_soan()), None)
            .unwrap();
        match *unsealable.secret_key {
            States::Unsealed {
                builder: _,
                bytes: _,
            } => (),
            _ => panic!("Key used for unsealable should have been unsealed"),
        };
        assert_eq!(
            get_sosak_ciphertext(b"hello, world!", None),
            unsealable.source.get().unwrap().to_vec(),
        );
    }

    #[test]
    fn test_seal_secretasymmetrickey_with_referenced_key() {
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let sosak = get_sosak();
        let unsealable = sosak
            .seal(
                plaintext,
                None,
                Some(&get_soan()),
                Some(".keys.somePath.".to_owned()),
            )
            .unwrap();
        match *unsealable.secret_key {
            States::Referenced { builder: _, path } => {
                assert_eq!(path, ".keys.somePath.".to_owned())
            }
            _ => panic!("Key used for unsealable should have been unsealed"),
        };
        assert_eq!(
            get_sosak_ciphertext(b"hello, world!", None),
            unsealable.source.get().unwrap().to_vec(),
        );
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_secretasymmetrickey_unseal_with_invalid_bytes() {
        let sosak = get_sosak();
        let ciphertext = ByteSource::Vector(VectorByteSource::new(b"bla"));
        let _ = sosak.unseal(ciphertext, None, &get_soan(), None).unwrap();
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_secretasymmetrickey_unseal_with_invalid_nonce() {
        let sosak = get_sosak();
        let ciphertext = get_sosak_ciphertext(b"hello, world!", None);
        let _ = sosak
            .unseal(
                ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
                None,
                &SodiumOxideAsymmetricNonce {
                    nonce: box_::gen_nonce(),
                },
                None,
            )
            .unwrap();
    }

    #[test]
    fn test_secretasymmetrickey_to_index() {
        let index = SodiumOxideSecretAsymmetricKey::get_index();
        assert_eq!(
            index,
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
        )
    }

    #[test]
    fn test_secretasymmetrickey_to_builder() {
        let sosak = SodiumOxideSecretAsymmetricKey::new();
        let builder = sosak.builder();
        let key_bytes = sosak.secret_key.as_ref();
        let built_key = builder.build(key_bytes).unwrap();
        assert_eq!(built_key.secret_key.as_ref(), sosak.secret_key.as_ref());
    }

    #[test]
    fn test_secretasymmetrickey_new() {
        let sosak = SodiumOxideSecretAsymmetricKey::new();
        assert!(!sosak.secret_key.as_ref().is_empty());
    }

    ///////////////////////////////////
    /// PUBLIC ASYMMETRIC KEY TESTS ///
    ///////////////////////////////////
    #[tokio::test]
    async fn test_seal_publicasymmetrickeysealable_with_unsealed_key() {
        let sopaks = get_sopaks_with_unsealed_key(b"hello, world!", None);
        let storer = MockStorer::new();
        let ciphertext = sopaks.seal(storer).await.unwrap();
        assert_eq!(
            ciphertext.get_source().get().unwrap(),
            get_sopak_ciphertext(b"hello, world!", None)
        );
    }

    #[tokio::test]
    async fn test_seal_publicasymmetrickeysealable_with_separate_secret_key() {
        let (_, other_sosak) = SodiumOxidePublicAsymmetricKey::new();
        let sopaks = get_sopaks_with_unsealed_key(b"hello, world!", Some(&other_sosak));
        let storer = MockStorer::new();
        let ciphertext = sopaks.seal(storer).await.unwrap();
        assert_eq!(
            ciphertext.get_source().get().unwrap(),
            get_sopak_ciphertext(b"hello, world!", Some(&other_sosak))
        );
    }

    #[tokio::test]
    async fn test_seal_publicasymmetrickeysealable_with_referenced_key() {
        let sopaks = get_sopaks_with_referenced_key(b"hello, world!", None, ".keys.default.");
        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SodiumOxidePublicAsymmetricKey>()
            .withf(|path: &str, index: &Option<Document>| {
                path == ".keys.default." && *index == SodiumOxidePublicAsymmetricKey::get_index()
            })
            .returning(|path, _| {
                Ok(Entry {
                    path: path.to_owned(),
                    value: get_unsealed_sopak(),
                })
            });
        let ciphertext = sopaks.seal(storer).await.unwrap();
        assert_eq!(
            ciphertext.get_source().get().unwrap(),
            get_sopak_ciphertext(b"hello, world!", None)
        );
    }

    #[tokio::test]
    async fn test_unseal_publicasymmetrickeyunsealable_with_unsealed_key() {
        let sopaku = get_sopaku_with_unsealed_key(b"hello, world!", None);
        let storer = MockStorer::new();
        let bs = sopaku.unseal(storer).await.unwrap();
        let source = bs.get_source();
        let sdb = StringDataBuilder {};
        let d = sdb.build(source.get().unwrap()).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

    #[tokio::test]
    async fn test_unseal_publicasymmetrickeyunsealable_with_separate_public_key() {
        let (_, other_sosak) = SodiumOxidePublicAsymmetricKey::new();
        let sopaku = get_sopaku_with_unsealed_key(b"hello, world!", Some(&other_sosak));
        let storer = MockStorer::new();
        let ciphertext = sopaku.unseal(storer).await.unwrap();
        assert_eq!(ciphertext.get_source().get().unwrap(), b"hello, world!",);
    }

    #[tokio::test]
    async fn test_unseal_publicasymmetrickeyunsealable_with_referenced_key() {
        let sopaku = get_sopaku_with_referenced_key(b"hello, world!", None, ".keys.default.");
        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SodiumOxidePublicAsymmetricKey>()
            .withf(|path: &str, index: &Option<Document>| {
                path == ".keys.default." && *index == SodiumOxidePublicAsymmetricKey::get_index()
            })
            .returning(|path, _| {
                Ok(Entry {
                    path: path.to_owned(),
                    value: get_unsealed_sopak(),
                })
            });
        let bs = sopaku.unseal(storer).await.unwrap();
        let source = bs.get_source();
        let sdb = StringDataBuilder {};
        let d = sdb.build(source.get().unwrap()).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

    #[test]
    fn test_sodiumoxidepublicasymmetrickeybuilder_build_valid() {
        let sopakb = SodiumOxidePublicAsymmetricKeyBuilder {};
        let (_, sk) = box_::gen_keypair();
        let key = sopakb.build(sk.as_ref()).unwrap();
        assert_eq!(key.public_key.as_ref(), sk.as_ref());
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidepublicasymmetrickeybuilder_build_invalid() {
        let sopakb = SodiumOxidePublicAsymmetricKeyBuilder {};
        let _ = sopakb.build(b"bla").unwrap();
    }

    #[test]
    fn test_sodiumoxidepublicasymmetrickeybuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Asymmetric(
            AsymmetricKeyBuilder::Public(PublicAsymmetricKeyBuilder::SodiumOxide(
                SodiumOxidePublicAsymmetricKeyBuilder {},
            )),
        )));
        let sopakb: SodiumOxidePublicAsymmetricKeyBuilder = tbc.try_into().unwrap();
        let (public_key, _) = SodiumOxidePublicAsymmetricKey::new();
        sopakb.build(public_key.public_key.as_ref()).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidepublicasymmetrickeybuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {})));
        let _: SodiumOxidePublicAsymmetricKeyBuilder = tbc.try_into().unwrap();
    }

    #[test]
    fn test_seal_publicasymmetrickey_with_non_referenced_key() {
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let (sopak, sosak) = get_sopak();
        let unsealable = sopak
            .seal(plaintext, &sosak, Some(&get_soan()), None)
            .unwrap();
        match *unsealable.public_key {
            States::Unsealed {
                builder: _,
                bytes: _,
            } => (),
            _ => panic!("Key used for unsealable should have been unsealed"),
        };
        assert_eq!(
            get_sopak_ciphertext(b"hello, world!", None),
            unsealable.source.get().unwrap().to_vec(),
        );
    }

    #[test]
    fn test_seal_publicasymmetrickey_with_referenced_key() {
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let (sopak, sosak) = get_sopak();
        let unsealable = sopak
            .seal(
                plaintext,
                &sosak,
                Some(&get_soan()),
                Some(".keys.somePath.".to_owned()),
            )
            .unwrap();
        match *unsealable.public_key {
            States::Unsealed {
                builder: _,
                bytes: _,
            } => (),
            _ => panic!("Key used for unsealable should have been unsealed"),
        };
        assert_eq!(
            get_sopak_ciphertext(b"hello, world!", Some(&sosak)),
            unsealable.source.get().unwrap().to_vec(),
        );
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_publicasymmetrickey_unseal_with_invalid_bytes() {
        let (sopak, sosak) = get_sopak();
        let ciphertext = ByteSource::Vector(VectorByteSource::new(b"bla"));
        let _ = sopak.unseal(ciphertext, &sosak, &get_soan(), None).unwrap();
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_publicasymmetrickey_unseal_with_invalid_nonce() {
        let (sopak, sosak) = get_sopak();
        let ciphertext = get_sopak_ciphertext(b"hello, world!", None);
        let _ = sopak
            .unseal(
                ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
                &sosak,
                &SodiumOxideAsymmetricNonce {
                    nonce: box_::gen_nonce(),
                },
                None,
            )
            .unwrap();
    }

    #[test]
    fn test_publicasymmetrickey_to_index() {
        let index = SodiumOxidePublicAsymmetricKey::get_index();
        assert_eq!(
            index,
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
        )
    }

    #[test]
    fn test_publicasymmetrickey_to_builder() {
        let (sopak, _) = SodiumOxidePublicAsymmetricKey::new();
        let builder = sopak.builder();
        let key_bytes = sopak.public_key.as_ref();
        let built_key = builder.build(key_bytes).unwrap();
        assert_eq!(built_key.public_key.as_ref(), sopak.public_key.as_ref());
    }

    #[test]
    fn test_publicasymmetrickey_new() {
        let (sopak, _) = SodiumOxidePublicAsymmetricKey::new();
        assert!(!sopak.public_key.as_ref().is_empty());
    }
}
