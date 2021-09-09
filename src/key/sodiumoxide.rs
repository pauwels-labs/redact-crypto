use crate::{
    nonce::sodiumoxide::{SodiumOxideAsymmetricNonce, SodiumOxideSymmetricNonce},
    Algorithm, AsymmetricKeyBuilder, Builder, ByteAlgorithm, ByteSource, CryptoError, Entry,
    HasBuilder, HasByteSource, HasIndex, HasPublicKey, KeyBuilder, PublicAsymmetricKeyBuilder,
    PublicAsymmetricSealer, PublicAsymmetricUnsealer, SecretAsymmetricKeyBuilder,
    SecretAsymmetricSealer, SecretAsymmetricUnsealer, Signer, StorableType, SymmetricKeyBuilder,
    SymmetricSealer, SymmetricUnsealer, ToPublicAsymmetricByteAlgorithm,
    ToSecretAsymmetricByteAlgorithm, ToSymmetricByteAlgorithm, TypeBuilder, TypeBuilderContainer,
};
use async_trait::async_trait;
use futures::Future;
use mongodb::bson::{self, Document};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_::{
        self,
        curve25519xsalsa20poly1305::{
            PublicKey as ExternalSodiumOxideCurve25519PublicAsymmetricKey,
            SecretKey as ExternalSodiumOxideCurve25519SecretAsymmetricKey,
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
    sign,
    sign::ed25519::{
        PublicKey as ExternalSodiumOxideEd25519PublicAsymmetricKey,
        SecretKey as ExternalSodiumOxideEd25519SecretAsymmetricKey,
    },
};
use std::{boxed::Box, convert::TryFrom};

// SYMMETRIC KEY \\
#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideSymmetricKeyAlgorithm {
    pub key: Box<Entry<SodiumOxideSymmetricKey>>,
    pub nonce: SodiumOxideSymmetricNonce,
}

#[async_trait]
impl Algorithm for SodiumOxideSymmetricKeyAlgorithm {
    type Source = ByteSource;
    type Output = ByteSource;

    async fn unseal(&self, source: &Self::Source) -> Result<Self::Output, CryptoError> {
        let key = self.key.resolve().await?;
        Ok(key.unseal(source, &self.nonce)?)
    }

    async fn seal(&self, source: &Self::Source) -> Result<Self::Output, CryptoError> {
        let key = self.key.resolve().await?;
        let (source, _) = key.seal(source, Some(&self.nonce))?;
        Ok(source)
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

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => Ok(SodiumOxideSymmetricKey {
                key: ExternalSodiumOxideSymmetricKey::from_slice(&bytes).ok_or(
                    CryptoError::InvalidKeyLength {
                        expected: SodiumOxideSymmetricKey::KEYBYTES,
                        actual: bytes.len(),
                    },
                )?,
            }),
            None => Ok(SodiumOxideSymmetricKey::new()),
        }
    }
}

impl From<SodiumOxideSymmetricKeyBuilder> for TypeBuilder {
    fn from(b: SodiumOxideSymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(b)))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideSymmetricKey {
    pub key: ExternalSodiumOxideSymmetricKey,
}

#[async_trait]
impl ToSymmetricByteAlgorithm for SodiumOxideSymmetricKey {
    type Key = Self;
    type Nonce = SodiumOxideSymmetricNonce;

    async fn to_byte_algorithm<F, Fut>(
        self,
        nonce: Option<Self::Nonce>,
        f: F,
    ) -> Result<ByteAlgorithm, CryptoError>
    where
        F: FnOnce(Self::Key) -> Fut + Send,
        Fut: Future<Output = Result<Entry<Self::Key>, CryptoError>> + Send,
    {
        let nonce = match nonce {
            Some(nonce) => nonce,
            None => SodiumOxideSymmetricNonce {
                nonce: secretbox::gen_nonce(),
            },
        };
        let entry = f(self).await?;
        Ok(ByteAlgorithm::SodiumOxideSymmetricKey(
            SodiumOxideSymmetricKeyAlgorithm {
                key: Box::new(entry),
                nonce,
            },
        ))
    }
}

impl StorableType for SodiumOxideSymmetricKey {}

impl SymmetricSealer for SodiumOxideSymmetricKey {
    type SealedOutput = ByteSource;
    type Nonce = SodiumOxideSymmetricNonce;

    fn seal(
        &self,
        plaintext: &ByteSource,
        nonce: Option<&Self::Nonce>,
    ) -> Result<(Self::SealedOutput, Self::Nonce), CryptoError> {
        let new_nonce = SodiumOxideSymmetricNonce {
            nonce: secretbox::gen_nonce(),
        };
        let nonce = match nonce {
            Some(n) => n,
            None => &new_nonce,
        };
        let plaintext = plaintext.get()?;
        let ciphertext = secretbox::seal(plaintext, &nonce.nonce, &self.key);
        Ok((ciphertext.as_slice().into(), nonce.to_owned()))
    }
}

impl SymmetricUnsealer for SodiumOxideSymmetricKey {
    type UnsealedOutput = ByteSource;
    type Nonce = SodiumOxideSymmetricNonce;

    fn unseal(
        &self,
        ciphertext: &ByteSource,
        nonce: &Self::Nonce,
    ) -> Result<Self::UnsealedOutput, CryptoError> {
        let plaintext = secretbox::open(ciphertext.get()?, &nonce.nonce, &self.key)
            .map_err(|_| CryptoError::CiphertextFailedVerification)?;
        Ok(plaintext.as_slice().into())
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

impl HasByteSource for SodiumOxideSymmetricKey {
    fn byte_source(&self) -> ByteSource {
        self.key.as_ref().into()
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
#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideSecretAsymmetricKeyAlgorithm {
    pub secret_key: Box<Entry<SodiumOxideCurve25519SecretAsymmetricKey>>,
    pub nonce: SodiumOxideAsymmetricNonce,
    pub public_key: Option<Box<Entry<SodiumOxideCurve25519PublicAsymmetricKey>>>,
}

#[async_trait]
impl Algorithm for SodiumOxideSecretAsymmetricKeyAlgorithm {
    type Source = ByteSource;
    type Output = ByteSource;

    async fn unseal(&self, source: &Self::Source) -> Result<Self::Output, CryptoError> {
        let secret_key = self.secret_key.resolve().await?;
        let public_key = match self.public_key {
            Some(ref public_key) => Ok::<_, CryptoError>(Some(public_key.resolve().await?)),
            None => Ok(None),
        }?;
        Ok(secret_key.unseal(&source, public_key, &self.nonce)?)
    }

    async fn seal(&self, source: &Self::Source) -> Result<Self::Output, CryptoError> {
        let secret_key = self.secret_key.resolve().await?;
        let public_key = match self.public_key {
            Some(ref public_key) => Ok::<_, CryptoError>(Some(public_key.resolve().await?)),
            None => Ok(None),
        }?;
        let (source, _) = secret_key.seal(&source, public_key, Some(&self.nonce))?;
        Ok(source)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct SodiumOxideCurve25519SecretAsymmetricKeyBuilder {}

impl TryFrom<TypeBuilderContainer> for SodiumOxideCurve25519SecretAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(sosakb),
            ))) => Ok(sosakb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for SodiumOxideCurve25519SecretAsymmetricKeyBuilder {
    type Output = SodiumOxideCurve25519SecretAsymmetricKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => Ok(SodiumOxideCurve25519SecretAsymmetricKey {
                secret_key: ExternalSodiumOxideCurve25519SecretAsymmetricKey::from_slice(&bytes)
                    .ok_or(CryptoError::InvalidKeyLength {
                        expected: SodiumOxideCurve25519SecretAsymmetricKey::KEYBYTES,
                        actual: bytes.len(),
                    })?,
            }),
            None => Ok(SodiumOxideCurve25519SecretAsymmetricKey::new()),
        }
    }
}

impl From<SodiumOxideCurve25519SecretAsymmetricKeyBuilder> for TypeBuilder {
    fn from(b: SodiumOxideCurve25519SecretAsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
            SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(b),
        )))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideCurve25519SecretAsymmetricKey {
    pub secret_key: ExternalSodiumOxideCurve25519SecretAsymmetricKey,
}

#[async_trait]
impl ToSecretAsymmetricByteAlgorithm for SodiumOxideCurve25519SecretAsymmetricKey {
    type SecretKey = Self;
    type Nonce = SodiumOxideAsymmetricNonce;
    type PublicKey = SodiumOxideCurve25519PublicAsymmetricKey;

    async fn to_byte_algorithm<F, Fut>(
        self,
        public_key: Option<Entry<Self::PublicKey>>,
        nonce: Option<Self::Nonce>,
        f: F,
    ) -> Result<ByteAlgorithm, CryptoError>
    where
        F: FnOnce(Self::SecretKey) -> Fut + Send,
        Fut: Future<Output = Result<Entry<Self::SecretKey>, CryptoError>> + Send,
    {
        let nonce = match nonce {
            Some(nonce) => nonce,
            None => SodiumOxideAsymmetricNonce {
                nonce: box_::gen_nonce(),
            },
        };
        let public_key = public_key.map(Box::new);
        let secret_key = Box::new(f(self).await?);
        Ok(ByteAlgorithm::SodiumOxideSecretAsymmetricKey(
            SodiumOxideSecretAsymmetricKeyAlgorithm {
                secret_key,
                nonce,
                public_key,
            },
        ))
    }
}

impl StorableType for SodiumOxideCurve25519SecretAsymmetricKey {}

impl SecretAsymmetricSealer for SodiumOxideCurve25519SecretAsymmetricKey {
    type SealedOutput = ByteSource;
    type Nonce = SodiumOxideAsymmetricNonce;
    type PublicKey = SodiumOxideCurve25519PublicAsymmetricKey;

    fn seal(
        &self,
        plaintext: &ByteSource,
        public_key: Option<&Self::PublicKey>,
        nonce: Option<&Self::Nonce>,
    ) -> Result<(Self::SealedOutput, Self::Nonce), CryptoError> {
        let new_nonce = SodiumOxideAsymmetricNonce {
            nonce: box_::gen_nonce(),
        };
        let nonce = match nonce {
            Some(n) => n,
            None => &new_nonce,
        };
        let plaintext = plaintext.get()?;
        let self_public_key = SodiumOxideCurve25519PublicAsymmetricKey {
            public_key: self.secret_key.public_key(),
        };
        let public_key = match public_key {
            Some(sopak) => sopak,
            None => &self_public_key,
        };
        let precomputed_key = box_::precompute(&public_key.public_key, &self.secret_key);
        let ciphertext = box_::seal_precomputed(plaintext, &nonce.nonce, &precomputed_key);
        Ok((ciphertext.as_slice().into(), nonce.to_owned()))
    }
}

impl SecretAsymmetricUnsealer for SodiumOxideCurve25519SecretAsymmetricKey {
    type UnsealedOutput = ByteSource;
    type Nonce = SodiumOxideAsymmetricNonce;
    type PublicKey = SodiumOxideCurve25519PublicAsymmetricKey;

    fn unseal(
        &self,
        ciphertext: &ByteSource,
        public_key: Option<&Self::PublicKey>,
        nonce: &Self::Nonce,
    ) -> Result<Self::UnsealedOutput, CryptoError> {
        let ciphertext = ciphertext.get()?;
        let self_public_key = SodiumOxideCurve25519PublicAsymmetricKey {
            public_key: self.secret_key.public_key(),
        };
        let public_key = match public_key {
            Some(sopak) => sopak,
            None => &self_public_key,
        };
        let precomputed_key = box_::precompute(&public_key.public_key, &self.secret_key);
        let plaintext = box_::open_precomputed(ciphertext, &nonce.nonce, &precomputed_key)
            .map_err(|_| CryptoError::CiphertextFailedVerification)?;
        Ok(plaintext.as_slice().into())
    }
}

impl HasIndex for SodiumOxideCurve25519SecretAsymmetricKey {
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
        "t": "SodiumOxideCurve25519"
        }
        }
        }
            }
        }
            })
    }
}

impl HasBuilder for SodiumOxideCurve25519SecretAsymmetricKey {
    type Builder = SodiumOxideCurve25519SecretAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        SodiumOxideCurve25519SecretAsymmetricKeyBuilder {}
    }
}

impl HasByteSource for SodiumOxideCurve25519SecretAsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        self.secret_key.as_ref().into()
    }
}

impl Default for SodiumOxideCurve25519SecretAsymmetricKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SodiumOxideCurve25519SecretAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDESECRETASYMMETRICKEYBYTES;

    pub fn new() -> Self {
        let (_, key) = box_::gen_keypair();
        SodiumOxideCurve25519SecretAsymmetricKey { secret_key: key }
    }

    pub fn get_signing_key(&self) -> Result<SodiumOxideEd25519SecretAsymmetricKey, CryptoError> {
        sign::ed25519::Seed::from_slice(&self.secret_key.as_ref())
            .ok_or(CryptoError::InvalidKeyLength {
                expected: sign::ed25519::SEEDBYTES,
                actual: self.secret_key.as_ref().len(),
            })
            .map(|seed| {
                let (_, sk) = sign::ed25519::keypair_from_seed(&seed);
                SodiumOxideEd25519SecretAsymmetricKey { secret_key: sk }
            })
    }
}

// PUBLIC ASYMMETRIC KEY \\
#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxidePublicAsymmetricKeyAlgorithm {
    pub public_key: Box<Entry<SodiumOxideCurve25519PublicAsymmetricKey>>,
    pub nonce: SodiumOxideAsymmetricNonce,
    pub secret_key: Box<Entry<SodiumOxideCurve25519SecretAsymmetricKey>>,
}

#[async_trait]
impl Algorithm for SodiumOxidePublicAsymmetricKeyAlgorithm {
    type Source = ByteSource;
    type Output = ByteSource;

    async fn unseal(&self, source: &Self::Source) -> Result<Self::Output, CryptoError> {
        let secret_key = self.secret_key.resolve().await?;
        let public_key = self.public_key.resolve().await?;
        Ok(public_key.unseal(source, secret_key, &self.nonce)?)
    }

    async fn seal(&self, source: &Self::Source) -> Result<Self::Output, CryptoError> {
        let secret_key = self.secret_key.resolve().await?;
        let public_key = self.public_key.resolve().await?;
        let (source, _) = public_key.seal(source, secret_key, Some(&self.nonce))?;
        Ok(source)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct SodiumOxideCurve25519PublicAsymmetricKeyBuilder {}

impl TryFrom<TypeBuilderContainer> for SodiumOxideCurve25519PublicAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(sopakb),
            ))) => Ok(sopakb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for SodiumOxideCurve25519PublicAsymmetricKeyBuilder {
    type Output = SodiumOxideCurve25519PublicAsymmetricKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => Ok(SodiumOxideCurve25519PublicAsymmetricKey {
                public_key: ExternalSodiumOxideCurve25519PublicAsymmetricKey::from_slice(&bytes)
                    .ok_or(CryptoError::InvalidKeyLength {
                        expected: SodiumOxideCurve25519PublicAsymmetricKey::KEYBYTES,
                        actual: bytes.len(),
                    })?,
            }),
            None => {
                let (pk, _) = SodiumOxideCurve25519PublicAsymmetricKey::new();
                Ok(pk)
            }
        }
    }
}

impl From<SodiumOxideCurve25519PublicAsymmetricKeyBuilder> for TypeBuilder {
    fn from(b: SodiumOxideCurve25519PublicAsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
            PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(b),
        )))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideCurve25519PublicAsymmetricKey {
    pub public_key: ExternalSodiumOxideCurve25519PublicAsymmetricKey,
}

#[async_trait]
impl ToPublicAsymmetricByteAlgorithm for SodiumOxideCurve25519PublicAsymmetricKey {
    type SecretKey = SodiumOxideCurve25519SecretAsymmetricKey;
    type Nonce = SodiumOxideAsymmetricNonce;
    type PublicKey = Self;

    async fn to_byte_algorithm<F, Fut>(
        self,
        secret_key: Entry<Self::SecretKey>,
        nonce: Option<Self::Nonce>,
        f: F,
    ) -> Result<ByteAlgorithm, CryptoError>
    where
        F: FnOnce(Self::PublicKey) -> Fut + Send,
        Fut: Future<Output = Result<Entry<Self::PublicKey>, CryptoError>> + Send,
    {
        let nonce = match nonce {
            Some(nonce) => nonce,
            None => SodiumOxideAsymmetricNonce {
                nonce: box_::gen_nonce(),
            },
        };
        let secret_key = Box::new(secret_key);
        let public_key = Box::new(f(self).await?);
        Ok(ByteAlgorithm::SodiumOxidePublicAsymmetricKey(
            SodiumOxidePublicAsymmetricKeyAlgorithm {
                secret_key,
                nonce,
                public_key,
            },
        ))
    }
}

impl StorableType for SodiumOxideCurve25519PublicAsymmetricKey {}

impl PublicAsymmetricSealer for SodiumOxideCurve25519PublicAsymmetricKey {
    type SealedOutput = ByteSource;
    type Nonce = SodiumOxideAsymmetricNonce;
    type SecretKey = SodiumOxideCurve25519SecretAsymmetricKey;

    fn seal(
        &self,
        plaintext: &ByteSource,
        secret_key: &Self::SecretKey,
        nonce: Option<&Self::Nonce>,
    ) -> Result<(Self::SealedOutput, Self::Nonce), CryptoError> {
        let new_nonce = SodiumOxideAsymmetricNonce {
            nonce: box_::gen_nonce(),
        };
        let nonce = match nonce {
            Some(n) => n,
            None => &new_nonce,
        };
        let plaintext = plaintext.get()?;
        let precomputed_key = box_::precompute(&self.public_key, &secret_key.secret_key);
        let ciphertext = box_::seal_precomputed(plaintext, &nonce.nonce, &precomputed_key);
        Ok((ciphertext.as_slice().into(), nonce.to_owned()))
    }
}

impl PublicAsymmetricUnsealer for SodiumOxideCurve25519PublicAsymmetricKey {
    type UnsealedOutput = ByteSource;
    type Nonce = SodiumOxideAsymmetricNonce;
    type SecretKey = SodiumOxideCurve25519SecretAsymmetricKey;

    fn unseal(
        &self,
        ciphertext: &ByteSource,
        secret_key: &Self::SecretKey,
        nonce: &Self::Nonce,
    ) -> Result<Self::UnsealedOutput, CryptoError> {
        let ciphertext = ciphertext.get()?;
        let precomputed_key = box_::precompute(&self.public_key, &secret_key.secret_key);
        let plaintext = box_::open_precomputed(ciphertext, &nonce.nonce, &precomputed_key)
            .map_err(|_| CryptoError::CiphertextFailedVerification)?;
        Ok(plaintext.as_slice().into())
    }
}

impl HasIndex for SodiumOxideCurve25519PublicAsymmetricKey {
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
        "t": "SodiumOxideCurve25519"
        }
        }
        }
            }
        }
            })
    }
}

impl HasBuilder for SodiumOxideCurve25519PublicAsymmetricKey {
    type Builder = SodiumOxideCurve25519PublicAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        SodiumOxideCurve25519PublicAsymmetricKeyBuilder {}
    }
}

impl HasByteSource for SodiumOxideCurve25519PublicAsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        self.public_key.as_ref().into()
    }
}

impl SodiumOxideCurve25519PublicAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES;

    pub fn new() -> (Self, SodiumOxideCurve25519SecretAsymmetricKey) {
        let (public_key, secret_key) = box_::gen_keypair();
        (
            SodiumOxideCurve25519PublicAsymmetricKey { public_key },
            SodiumOxideCurve25519SecretAsymmetricKey { secret_key },
        )
    }
}

impl HasPublicKey for SodiumOxideCurve25519SecretAsymmetricKey {
    type PublicKey = SodiumOxideCurve25519PublicAsymmetricKey;

    fn public_key(&self) -> Result<Self::PublicKey, CryptoError> {
        Ok(SodiumOxideCurve25519PublicAsymmetricKey {
            public_key: self.secret_key.public_key(),
        })
    }
}

// SECRET SIGNING KEY \\
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct SodiumOxideEd25519SecretAsymmetricKeyBuilder {}

impl TryFrom<TypeBuilderContainer> for SodiumOxideEd25519SecretAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxideEd25519(sopakb),
            ))) => Ok(sopakb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for SodiumOxideEd25519SecretAsymmetricKeyBuilder {
    type Output = SodiumOxideEd25519SecretAsymmetricKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => Ok(SodiumOxideEd25519SecretAsymmetricKey {
                secret_key: ExternalSodiumOxideEd25519SecretAsymmetricKey::from_slice(&bytes)
                    .ok_or(CryptoError::InvalidKeyLength {
                        expected: SodiumOxideEd25519SecretAsymmetricKey::KEYBYTES,
                        actual: bytes.len(),
                    })?,
            }),
            None => {
                let sk = SodiumOxideEd25519SecretAsymmetricKey::new();
                Ok(sk)
            }
        }
    }
}

impl From<SodiumOxideEd25519SecretAsymmetricKeyBuilder> for TypeBuilder {
    fn from(b: SodiumOxideEd25519SecretAsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
            SecretAsymmetricKeyBuilder::SodiumOxideEd25519(b),
        )))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideEd25519SecretAsymmetricKey {
    pub secret_key: ExternalSodiumOxideEd25519SecretAsymmetricKey,
}

impl StorableType for SodiumOxideEd25519SecretAsymmetricKey {}

impl Signer for SodiumOxideEd25519SecretAsymmetricKey {
    fn sign(&self, bytes: ByteSource) -> Result<ByteSource, CryptoError> {
        Ok(sign::sign(bytes.get()?, &self.secret_key).as_slice().into())
    }
}

impl HasIndex for SodiumOxideEd25519SecretAsymmetricKey {
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
        "t": "SodiumOxideEd25519"
        }
        }
        }
            }
        }
            })
    }
}

impl HasBuilder for SodiumOxideEd25519SecretAsymmetricKey {
    type Builder = SodiumOxideEd25519SecretAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        SodiumOxideEd25519SecretAsymmetricKeyBuilder {}
    }
}

impl HasByteSource for SodiumOxideEd25519SecretAsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        self.secret_key.as_ref().into()
    }
}

impl SodiumOxideEd25519SecretAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES;

    pub fn new() -> Self {
        let (_, secret_key) = sign::gen_keypair();
        SodiumOxideEd25519SecretAsymmetricKey { secret_key }
    }
}

impl Default for SodiumOxideEd25519SecretAsymmetricKey {
    fn default() -> Self {
        Self::new()
    }
}

// PUBLIC SIGNING KEY \\
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct SodiumOxideEd25519PublicAsymmetricKeyBuilder {}

impl TryFrom<TypeBuilderContainer> for SodiumOxideEd25519PublicAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                PublicAsymmetricKeyBuilder::SodiumOxideEd25519(sopakb),
            ))) => Ok(sopakb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for SodiumOxideEd25519PublicAsymmetricKeyBuilder {
    type Output = SodiumOxideEd25519PublicAsymmetricKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => Ok(SodiumOxideEd25519PublicAsymmetricKey {
                public_key: ExternalSodiumOxideEd25519PublicAsymmetricKey::from_slice(&bytes)
                    .ok_or(CryptoError::InvalidKeyLength {
                        expected: SodiumOxideEd25519PublicAsymmetricKey::KEYBYTES,
                        actual: bytes.len(),
                    })?,
            }),
            None => {
                let (pk, _) = SodiumOxideEd25519PublicAsymmetricKey::new();
                Ok(pk)
            }
        }
    }
}

impl From<SodiumOxideEd25519PublicAsymmetricKeyBuilder> for TypeBuilder {
    fn from(b: SodiumOxideEd25519PublicAsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
            PublicAsymmetricKeyBuilder::SodiumOxideEd25519(b),
        )))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideEd25519PublicAsymmetricKey {
    pub public_key: ExternalSodiumOxideEd25519PublicAsymmetricKey,
}

impl StorableType for SodiumOxideEd25519PublicAsymmetricKey {}

impl HasIndex for SodiumOxideEd25519PublicAsymmetricKey {
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
        "t": "SodiumOxideEd25519"
        }
        }
        }
            }
        }
            })
    }
}

impl HasBuilder for SodiumOxideEd25519PublicAsymmetricKey {
    type Builder = SodiumOxideEd25519PublicAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        SodiumOxideEd25519PublicAsymmetricKeyBuilder {}
    }
}

impl HasByteSource for SodiumOxideEd25519PublicAsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        self.public_key.as_ref().into()
    }
}

impl SodiumOxideEd25519PublicAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES;

    pub fn new() -> (Self, SodiumOxideEd25519SecretAsymmetricKey) {
        let (public_key, secret_key) = sign::gen_keypair();
        (
            SodiumOxideEd25519PublicAsymmetricKey { public_key },
            SodiumOxideEd25519SecretAsymmetricKey { secret_key },
        )
    }
}

impl HasPublicKey for SodiumOxideEd25519SecretAsymmetricKey {
    type PublicKey = SodiumOxideEd25519PublicAsymmetricKey;

    fn public_key(&self) -> Result<Self::PublicKey, CryptoError> {
        Ok(SodiumOxideEd25519PublicAsymmetricKey {
            public_key: self.secret_key.public_key(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SodiumOxideCurve25519PublicAsymmetricKey, SodiumOxideCurve25519PublicAsymmetricKeyBuilder,
        SodiumOxideCurve25519SecretAsymmetricKey, SodiumOxideCurve25519SecretAsymmetricKeyBuilder,
        SodiumOxideSymmetricKey, SodiumOxideSymmetricKeyBuilder,
    };
    use crate::{
        nonce::sodiumoxide::{SodiumOxideAsymmetricNonce, SodiumOxideSymmetricNonce},
        storage::tests::MockStorer, storage::tests::MockIndexedStorer,
        Algorithm, AsymmetricKeyBuilder, BoolDataBuilder, Builder, ByteSource, Data, DataBuilder,
        HasBuilder, HasByteSource, HasIndex, HasPublicKey, KeyBuilder, PublicAsymmetricKeyBuilder,
        PublicAsymmetricSealer, PublicAsymmetricUnsealer, SecretAsymmetricKeyBuilder,
        SecretAsymmetricSealer, SecretAsymmetricUnsealer, SymmetricKeyBuilder, SymmetricSealer,
        SymmetricUnsealer, ToEntry, ToSymmetricByteAlgorithm, TypeBuilder, TypeBuilderContainer,
    };
    use mongodb::bson;
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
        secret_key: Option<&SodiumOxideCurve25519SecretAsymmetricKey>,
    ) -> Vec<u8> {
        let new_key = get_sosak();
        let secret_key = match secret_key {
            Some(sk) => sk,
            None => &new_key,
        };
        let (public_key, _) = get_sopak();
        let nonce = get_soan();
        let precomputed_key = box_::precompute(&public_key.public_key, &secret_key.secret_key);
        box_::seal_precomputed(plaintext, &nonce.nonce, &precomputed_key)
    }

    fn get_sopak() -> (
        SodiumOxideCurve25519PublicAsymmetricKey,
        SodiumOxideCurve25519SecretAsymmetricKey,
    ) {
        let key_bytes: [u8; 32] = [
            77, 166, 178, 227, 216, 254, 219, 202, 41, 198, 74, 141, 126, 196, 68, 179, 19, 218,
            34, 107, 174, 121, 199, 180, 254, 254, 161, 219, 225, 158, 220, 56,
        ];
        let sosakb = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {};
        let secret_key = sosakb.build(Some(&key_bytes)).unwrap();
        let public_key = SodiumOxideCurve25519PublicAsymmetricKey {
            public_key: secret_key.secret_key.public_key(),
        };

        (public_key, secret_key)
    }

    // fn get_unsealed_sopak(path: EntryPath) -> Entry<SodiumOxideCurve25519PublicAsymmetricKey> {
    //     let (public_key, _) = get_sopak();
    //     public_key.to_unsealed_entry(path).unwrap()
    // }

    // fn get_referenced_sopak(
    //     path: EntryPath,
    //     storer: MockStorer,
    // ) -> Entry<SodiumOxideCurve25519PublicAsymmetricKey> {
    //     let (public_key, _) = get_sopak();
    //     public_key.to_ref_entry(path, storer).unwrap()
    // }

    // async fn get_sealed_sopak_with_unsealed_key(
    //     path: EntryPath,
    // ) -> Entry<SodiumOxideCurve25519PublicAsymmetricKey> {
    //     let (public_key, _) = get_sopak();
    //     let encryption_key = get_sosk();
    //     let algorithm = encryption_key
    //         .to_byte_algorithm(Some(get_sosn()), |key| async move {
    //             key.to_unsealed_entry(".encryptionkey.".to_owned())
    //         })
    //         .await
    //         .unwrap();
    //     public_key.to_sealed_entry(path, algorithm).await.unwrap()
    // }

    // async fn get_sealed_sopak_with_referenced_key(
    //     path: EntryPath,
    //     storer: MockStorer,
    // ) -> Entry<SodiumOxideCurve25519PublicAsymmetricKey> {
    //     let (public_key, _) = get_sopak();
    //     let encryption_key = get_sosk();
    //     let algorithm = encryption_key
    //         .to_byte_algorithm(Some(get_sosn()), |key| async move {
    //             key.to_ref_entry(".encryptionkey.".to_owned(), TypeStorer::Mock(storer))
    //         })
    //         .await
    //         .unwrap();
    //     public_key.to_sealed_entry(path, algorithm).await.unwrap()
    // }

    //////////////////////////////////////////////
    /// SECRET ASYMMETRIC KEY HELPER FUNCTIONS ///
    //////////////////////////////////////////////
    fn get_sosak_ciphertext(
        plaintext: &[u8],
        public_key: &Option<SodiumOxideCurve25519PublicAsymmetricKey>,
    ) -> Vec<u8> {
        let key = get_sosak();
        let nonce = get_soan();
        let own_key = SodiumOxideCurve25519PublicAsymmetricKey {
            public_key: key.secret_key.public_key(),
        };
        let public_key = match public_key {
            Some(k) => k,
            None => &own_key,
        };
        let precomputed_key = box_::precompute(&public_key.public_key, &key.secret_key);
        box_::seal_precomputed(plaintext, &nonce.nonce, &precomputed_key)
    }

    fn get_sosak() -> SodiumOxideCurve25519SecretAsymmetricKey {
        let key_bytes: [u8; 32] = [
            77, 166, 178, 227, 216, 254, 219, 202, 41, 198, 74, 141, 126, 196, 68, 179, 19, 218,
            34, 107, 174, 121, 199, 180, 254, 254, 161, 219, 225, 158, 220, 56,
        ];
        let sosakb = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {};
        sosakb.build(Some(&key_bytes)).unwrap()
    }

    fn get_soan() -> SodiumOxideAsymmetricNonce {
        let nonce_bytes: [u8; 24] = [
            24, 101, 189, 110, 189, 19, 129, 254, 163, 80, 137, 144, 100, 21, 11, 191, 22, 47, 64,
            132, 80, 122, 1, 237,
        ];
        let nonce = box_::curve25519xsalsa20poly1305::Nonce::from_slice(&nonce_bytes).unwrap();
        SodiumOxideAsymmetricNonce { nonce }
    }

    // fn get_unsealed_sosak(path: EntryPath) -> Entry<SodiumOxideCurve25519SecretAsymmetricKey> {
    //     let key = get_sosak();
    //     key.to_unsealed_entry(path).unwrap()
    // }

    // fn get_referenced_sosak(
    //     path: EntryPath,
    //     storer: MockStorer,
    // ) -> Entry<SodiumOxideCurve25519SecretAsymmetricKey> {
    //     let key = get_sosak();
    //     key.to_ref_entry(path, storer).unwrap()
    // }

    // async fn get_sealed_sosak_with_unsealed_key(
    //     path: EntryPath,
    // ) -> Entry<SodiumOxideCurve25519SecretAsymmetricKey> {
    //     let key = get_sosak();
    //     let encryption_key = get_sosk();
    //     let algorithm = encryption_key
    //         .to_byte_algorithm(Some(get_sosn()), |key| async move {
    //             key.to_unsealed_entry(".encryptionkey.".to_owned())
    //         })
    //         .await
    //         .unwrap();
    //     key.to_sealed_entry(path, algorithm).await.unwrap()
    // }

    // async fn get_sealed_sosak_with_referenced_key(
    //     path: EntryPath,
    //     storer: MockStorer,
    // ) -> Entry<SodiumOxideCurve25519SecretAsymmetricKey> {
    //     let key = get_sosak();
    //     let encryption_key = get_sosk();
    //     let algorithm = encryption_key
    //         .to_byte_algorithm(Some(get_sosn()), |key| async move {
    //             key.to_ref_entry(".encryptionkey.".to_owned(), TypeStorer::Mock(storer))
    //         })
    //         .await
    //         .unwrap();
    //     key.to_sealed_entry(path, algorithm).await.unwrap()
    // }

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
        soskb.build(Some(&key_bytes)).unwrap()
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

    // /// Returns the key from get_sosk() wrapped in a States::Unsealed
    // fn get_unsealed_sosk(path: EntryPath) -> Entry<SodiumOxideSymmetricKey> {
    //     let sosk = get_sosk();
    //     sosk.to_unsealed_entry(path).unwrap()
    // }

    // /// Returns the key from get_sosk() wrapped in a States::Referenced
    // fn get_referenced_sosk(path: EntryPath, storer: MockStorer) -> Entry<SodiumOxideSymmetricKey> {
    //     let sosk = get_sosk();
    //     sosk.to_ref_entry(path, storer).unwrap()
    // }

    // /// Returns the key from get_sosk() wrapped in a States::Sealed and decrypted
    // /// by an unsealed version of the key from get_sosk()
    // async fn get_sealed_sosk_with_unsealed_key(path: EntryPath) -> Entry<SodiumOxideSymmetricKey> {
    //     let sosk = get_sosk();
    //     let encryption_key = get_sosk();
    //     let algorithm = encryption_key
    //         .to_byte_algorithm(Some(get_sosn()), |key| async move {
    //             key.to_unsealed_entry(".encryptionkey.".to_owned())
    //         })
    //         .await
    //         .unwrap();
    //     sosk.to_sealed_entry(path, algorithm).await.unwrap()
    // }

    // /// Returns the key from get_sosk() wrapped in a States::Sealed and decrypted
    // /// by a States::Referenced with the given path
    // async fn get_sealed_sosk_with_referenced_key(
    //     path: EntryPath,
    //     storer: MockStorer,
    // ) -> Entry<SodiumOxideSymmetricKey> {
    //     let sosk = get_sosk();
    //     let encryption_key = get_sosk();
    //     let algorithm = encryption_key
    //         .to_byte_algorithm(Some(get_sosn()), |key| async move {
    //             key.to_ref_entry(".encryptionkey.".to_owned(), storer)
    //         })
    //         .await
    //         .unwrap();
    //     sosk.to_sealed_entry(path, algorithm).await.unwrap()
    // }

    ///////////////////////////
    /// SYMMETRIC KEY TESTS ///
    ///////////////////////////

    /// SYMMETRIC BYTE ALGORITHM - SEAL ///
    #[tokio::test]
    async fn test_seal_symmetricbytealgorithm_with_unsealed_key() {
        let data = Data::String("hello, world!".to_owned());
        let key = get_sosk();
        let algorithm = key
            .to_byte_algorithm(Some(get_sosn()), |key| async move {
                key.to_unsealed_entry(".encryptionkey.".to_owned())
            })
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sosk_ciphertext(b"hello, world!")
        );
    }

    #[tokio::test]
    async fn test_seal_symmetricbytealgorithm_with_referenced_key() {
        let data = Data::String("hello, world!".to_owned());
        let unsealed_key = get_sosk()
            .to_unsealed_entry(".encryptionkey.".to_owned())
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideSymmetricKey>()
            .withf(|path| {
                path == ".encryptionkey."
            })
            .return_once(move |_| Ok(unsealed_key));
        let ref_key = get_sosk()
            .to_ref_entry(".encryptionkey.".to_owned(), storer)
            .unwrap();
        let algorithm = ref_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sosk_ciphertext(b"hello, world!")
        );
    }

    #[tokio::test]
    async fn test_seal_symmetricbytealgorithm_with_sealed_key_with_unsealed_decryption_key() {
        let data = Data::String("hello, world!".to_owned());
        let key = get_sosk();
        let key_encryption_key = get_sosk();
        let key_encryption_algorithm = key_encryption_key
            .to_byte_algorithm(Some(get_sosn()), |key| async move {
                key.to_unsealed_entry(".keyencryptionkey.".to_owned())
            })
            .await
            .unwrap();
        let algorithm = key
            .to_byte_algorithm(Some(get_sosn()), |key| async move {
                key.to_sealed_entry(".encryptionkey.".to_owned(), key_encryption_algorithm)
                    .await
            })
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sosk_ciphertext(b"hello, world!")
        );
    }

    #[tokio::test]
    async fn test_seal_symmetricbytealgorithm_with_sealed_key_with_referenced_decryption_key() {
        let unsealed_key_encryption_key = get_sosk()
            .to_unsealed_entry(".keyencryptionkey.".to_owned())
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideSymmetricKey>()
            .withf(|path| {
                path == ".keyencryptionkey."
            })
            .return_once(move |_| Ok(unsealed_key_encryption_key));
        let data = Data::String("hello, world!".to_owned());
        let key = get_sosk();
        let referenced_key_encryption_key = get_sosk()
            .to_ref_entry(".keyencryptionkey.".to_owned(), storer)
            .unwrap();
        let key_encryption_algorithm = referenced_key_encryption_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let algorithm = key
            .to_byte_algorithm(Some(get_sosn()), |key| async move {
                key.to_sealed_entry(".encryptionkey.".to_owned(), key_encryption_algorithm)
                    .await
            })
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sosk_ciphertext(b"hello, world!")
        );
    }

    /// SYMMETRIC BYTE ALGORITHM - UNSEAL ///
    #[tokio::test]
    async fn test_unseal_symmetricbytealgorithm_with_unsealed_key() {
        let data = Data::String("hello, world!".to_owned());
        let key = get_sosk();
        let algorithm = key
            .to_byte_algorithm(Some(get_sosn()), |key| async move {
                key.to_unsealed_entry(".encryptionkey.".to_owned())
            })
            .await
            .unwrap();
        let ciphertext = get_sosk_ciphertext(data.byte_source().get().unwrap());
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap());
    }

    #[tokio::test]
    async fn test_unseal_symmetricbytealgorithm_with_referenced_key() {
        let data = Data::String("hello, world!".to_owned());
        let unsealed_key = get_sosk()
            .to_unsealed_entry(".encryptionkey.".to_owned())
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideSymmetricKey>()
            .withf(|path| {
                path == ".encryptionkey."
            })
            .return_once(move |_| Ok(unsealed_key));
        let ref_key = get_sosk()
            .to_ref_entry(".encryptionkey.".to_owned(), storer)
            .unwrap();
        let algorithm = ref_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let ciphertext = get_sosk_ciphertext(data.byte_source().get().unwrap());
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap());
    }

    #[tokio::test]
    async fn test_unseal_symmetricbytealgorithm_with_sealed_key_with_unsealed_decryption_key() {
        let data = Data::String("hello, world!".to_owned());
        let key = get_sosk();
        let key_encryption_key = get_sosk();
        let key_encryption_algorithm = key_encryption_key
            .to_byte_algorithm(Some(get_sosn()), |key| async move {
                key.to_unsealed_entry(".keyencryptionkey.".to_owned())
            })
            .await
            .unwrap();
        let algorithm = key
            .to_byte_algorithm(Some(get_sosn()), |key| async move {
                key.to_sealed_entry(".encryptionkey.".to_owned(), key_encryption_algorithm)
                    .await
            })
            .await
            .unwrap();
        let ciphertext = get_sosk_ciphertext(data.byte_source().get().unwrap());
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap());
    }

    #[tokio::test]
    async fn test_unseal_symmetricbytealgorithm_with_sealed_key_with_referenced_decryption_key() {
        let unsealed_key_encryption_key = get_sosk()
            .to_unsealed_entry(".keyencryptionkey.".to_owned())
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideSymmetricKey>()
            .withf(|path| {
                path == ".keyencryptionkey."
            })
            .return_once(move |_| Ok(unsealed_key_encryption_key));
        let data = Data::String("hello, world!".to_owned());
        let key = get_sosk();
        let referenced_key_encryption_key = get_sosk()
            .to_ref_entry(".keyencryptionkey.".to_owned(), storer)
            .unwrap();
        let key_encryption_algorithm = referenced_key_encryption_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let algorithm = key
            .to_byte_algorithm(Some(get_sosn()), |key| async move {
                key.to_sealed_entry(".encryptionkey.".to_owned(), key_encryption_algorithm)
                    .await
            })
            .await
            .unwrap();
        let ciphertext = get_sosk_ciphertext(data.byte_source().get().unwrap());
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap());
    }

    /// SYMMETRIC KEY - BUILDER ///
    #[test]
    fn test_sodiumoxidesymmetrickeybuilder_build_valid() {
        let soskb = SodiumOxideSymmetricKeyBuilder {};
        let external_key = secretbox::gen_key();
        let key = soskb.build(Some(external_key.as_ref())).unwrap();
        assert_eq!(key.key.as_ref(), external_key.as_ref());
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidesymmetrickeybuilder_build_invalid() {
        let soskb = SodiumOxideSymmetricKeyBuilder {};
        let _ = soskb.build(Some(b"bla")).unwrap();
    }

    #[test]
    fn test_sodiumoxidesymmetrickeybuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Symmetric(
            SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
        )));
        let soskb: SodiumOxideSymmetricKeyBuilder = tbc.try_into().unwrap();
        let key = SodiumOxideSymmetricKey::new();
        soskb.build(Some(key.key.as_ref())).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidesymmetrickeybuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {})));
        let _: SodiumOxideSymmetricKeyBuilder = tbc.try_into().unwrap();
    }

    /// SYMMETRIC KEY - SEAL AND UNSEAL ///
    #[test]
    fn test_seal_symmetrickey() {
        let plaintext = "hello, world!".into();
        let sosk = get_sosk();
        let (cipher_source, _) = sosk.seal(&plaintext, Some(&get_sosn())).unwrap();
        assert_eq!(
            get_sosk_ciphertext(b"hello, world!"),
            cipher_source.get().unwrap().to_vec(),
        );
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_symmetrickey_unseal_with_invalid_bytes() {
        let sosk = get_sosk();
        let ciphertext = "bla".into();
        let _ = sosk.unseal(&ciphertext, &get_sosn()).unwrap();
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_symmetrickey_unseal_with_invalid_nonce() {
        let sosk = get_sosk();
        let ciphertext = get_sosk_ciphertext(b"hello, world!");
        let _ = sosk
            .unseal(
                &ciphertext.as_slice().into(),
                &SodiumOxideSymmetricNonce {
                    nonce: secretbox::gen_nonce(),
                },
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
        let built_key = builder.build(Some(key_bytes)).unwrap();
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

    /// SECRET ASYMMETRIC BYTE ALGORITHM - SEAL ///
    #[tokio::test]
    async fn test_seal_secretasymmetricbytealgorithm_with_unsealed_key() {
        let data = Data::String("hello, world!".to_owned());
        let alice_key = get_sosak()
            .to_unsealed_entry(".alicesecretkey.".to_owned())
            .unwrap();
        let bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .public_key()
            .unwrap()
            .to_unsealed_entry(".bobpublickey.".to_owned())
            .unwrap();
        let bob_key_bytes = bob_key.resolve().await.unwrap().byte_source();
        let algorithm = alice_key
            .to_secret_asymmetric_byte_algorithm(Some(bob_key), Some(get_soan()))
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        let bob_key_copy = SodiumOxideCurve25519PublicAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sosak_ciphertext(b"hello, world!", &Some(bob_key_copy))
        );
    }

    #[tokio::test]
    async fn test_seal_secretasymmetricbytealgorithm_with_referenced_key() {
        let data = Data::String("hello, world!".to_owned());
        let unsealed_alice_key = get_sosak()
            .to_unsealed_entry(".alicesecretkey.".to_owned())
            .unwrap();
        let unsealed_bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .public_key()
            .unwrap()
            .to_unsealed_entry(".bobpublickey.".to_owned())
            .unwrap();
        let bob_key_bytes = unsealed_bob_key.resolve().await.unwrap().byte_source();
        let mut storer = MockIndexedStorer::new();
        storer
            .expect_private_get::<SodiumOxideCurve25519SecretAsymmetricKey>()
            .withf(|path| {
                path == ".alicesecretkey."
            })
            .return_once(move |_| Ok(unsealed_alice_key));
        let ref_alice_key = get_sosak()
            .to_ref_entry(".alicesecretkey.".to_owned(), storer)
            .unwrap();
        let algorithm = ref_alice_key
            .to_secret_asymmetric_byte_algorithm(Some(unsealed_bob_key), Some(get_soan()))
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        let bob_key_copy = SodiumOxideCurve25519PublicAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sosak_ciphertext(b"hello, world!", &Some(bob_key_copy))
        );
    }

    #[tokio::test]
    async fn test_seal_secretasymmetricbytealgorithm_with_sealed_key_with_unsealed_decryption_key()
    {
        let data = Data::String("hello, world!".to_owned());
        let alice_decryption_key = get_sosk()
            .to_unsealed_entry(".alicedecryptionkey.".to_owned())
            .unwrap();
        let alice_decryption_algorithm = alice_decryption_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let alice_key = get_sosak()
            .to_sealed_entry(".alicesecretkey.".to_owned(), alice_decryption_algorithm)
            .await
            .unwrap();
        let bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .public_key()
            .unwrap()
            .to_unsealed_entry(".bobpublickey.".to_owned())
            .unwrap();
        let bob_key_bytes = bob_key.resolve().await.unwrap().byte_source();
        let algorithm = alice_key
            .to_secret_asymmetric_byte_algorithm(Some(bob_key), Some(get_soan()))
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        let bob_key_copy = SodiumOxideCurve25519PublicAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sosak_ciphertext(b"hello, world!", &Some(bob_key_copy))
        );
    }

    #[tokio::test]
    async fn test_seal_secretasymmetricbytealgorithm_with_sealed_key_with_referenced_decryption_key(
    ) {
        let data = Data::String("hello, world!".to_owned());
        let unsealed_alice_decryption_key = get_sosk()
            .to_unsealed_entry(".alicedecryptionkey.".to_owned())
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideSymmetricKey>()
            .withf(|path| {
                path == ".alicedecryptionkey."
            })
            .return_once(move |_| Ok(unsealed_alice_decryption_key));
        let ref_alice_decryption_key = get_sosk()
            .to_ref_entry(".alicedecryptionkey.".to_owned(), storer)
            .unwrap();
        let alice_decryption_algorithm = ref_alice_decryption_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let sealed_alice_key = get_sosak()
            .to_sealed_entry(".alicesecretkey.".to_owned(), alice_decryption_algorithm)
            .await
            .unwrap();
        let unsealed_bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .public_key()
            .unwrap()
            .to_unsealed_entry(".bobpublickey.".to_owned())
            .unwrap();
        let bob_key_bytes = unsealed_bob_key.resolve().await.unwrap().byte_source();
        let algorithm = sealed_alice_key
            .to_secret_asymmetric_byte_algorithm(Some(unsealed_bob_key), Some(get_soan()))
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        let bob_key_copy = SodiumOxideCurve25519PublicAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sosak_ciphertext(b"hello, world!", &Some(bob_key_copy))
        );
    }

    /// SECRET ASYMMETRIC BYTE ALGORITHM - UNSEAL ///
    #[tokio::test]
    async fn test_unseal_secretasymmetricbytealgorithm_with_unsealed_key() {
        let data = Data::String("hello, world!".to_owned());
        let alice_key = get_sosak()
            .to_unsealed_entry(".alicesecretkey.".to_owned())
            .unwrap();
        let bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .public_key()
            .unwrap()
            .to_unsealed_entry(".bobpublickey.".to_owned())
            .unwrap();
        let bob_key_bytes = bob_key.resolve().await.unwrap().byte_source();
        let bob_key_copy = SodiumOxideCurve25519PublicAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        let ciphertext = get_sosak_ciphertext(b"hello, world!", &Some(bob_key_copy));
        let algorithm = alice_key
            .to_secret_asymmetric_byte_algorithm(Some(bob_key), Some(get_soan()))
            .await
            .unwrap();
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap());
    }

    #[tokio::test]
    async fn test_unseal_secretasymmetricbytealgorithm_with_referenced_key() {
        let data = Data::String("hello, world!".to_owned());
        let unsealed_alice_key = get_sosak()
            .to_unsealed_entry(".alicesecretkey.".to_owned())
            .unwrap();
        let unsealed_bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .public_key()
            .unwrap()
            .to_unsealed_entry(".bobpublickey.".to_owned())
            .unwrap();
        let bob_key_bytes = unsealed_bob_key.resolve().await.unwrap().byte_source();
        let bob_key_copy = SodiumOxideCurve25519PublicAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideCurve25519SecretAsymmetricKey>()
            .withf(|path| {
                path == ".alicesecretkey."
            })
            .return_once(move |_| Ok(unsealed_alice_key));
        let ref_alice_key = get_sosak()
            .to_ref_entry(".alicesecretkey.".to_owned(), storer)
            .unwrap();
        let ciphertext = get_sosak_ciphertext(b"hello, world!", &Some(bob_key_copy));
        let algorithm = ref_alice_key
            .to_secret_asymmetric_byte_algorithm(Some(unsealed_bob_key), Some(get_soan()))
            .await
            .unwrap();
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap());
    }

    #[tokio::test]
    async fn test_unseal_secretasymmetricbytealgorithm_with_sealed_key_with_unsealed_decryption_key(
    ) {
        let data = Data::String("hello, world!".to_owned());
        let alice_decryption_key = get_sosk()
            .to_unsealed_entry(".alicedecryptionkey.".to_owned())
            .unwrap();
        let alice_decryption_algorithm = alice_decryption_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let alice_key = get_sosak()
            .to_sealed_entry(".alicesecretkey.".to_owned(), alice_decryption_algorithm)
            .await
            .unwrap();
        let bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .public_key()
            .unwrap()
            .to_unsealed_entry(".bobpublickey.".to_owned())
            .unwrap();
        let bob_key_bytes = bob_key.resolve().await.unwrap().byte_source();
        let bob_key_copy = SodiumOxideCurve25519PublicAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        let ciphertext = get_sosak_ciphertext(b"hello, world!", &Some(bob_key_copy));
        let algorithm = alice_key
            .to_secret_asymmetric_byte_algorithm(Some(bob_key), Some(get_soan()))
            .await
            .unwrap();
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap());
    }

    #[tokio::test]
    async fn test_unseal_secretasymmetricbytealgorithm_with_sealed_key_with_referenced_decryption_key(
    ) {
        let data = Data::String("hello, world!".to_owned());
        let unsealed_alice_decryption_key = get_sosk()
            .to_unsealed_entry(".alicedecryptionkey.".to_owned())
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideSymmetricKey>()
            .withf(|path| {
                path == ".alicedecryptionkey."
            })
            .return_once(move |_| Ok(unsealed_alice_decryption_key));
        let ref_alice_decryption_key = get_sosk()
            .to_ref_entry(".alicedecryptionkey.".to_owned(), storer)
            .unwrap();
        let alice_decryption_algorithm = ref_alice_decryption_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let sealed_alice_key = get_sosak()
            .to_sealed_entry(".alicesecretkey.".to_owned(), alice_decryption_algorithm)
            .await
            .unwrap();
        let unsealed_bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .public_key()
            .unwrap()
            .to_unsealed_entry(".bobpublickey.".to_owned())
            .unwrap();
        let bob_key_bytes = unsealed_bob_key.resolve().await.unwrap().byte_source();
        let bob_key_copy = SodiumOxideCurve25519PublicAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        let ciphertext = get_sosak_ciphertext(b"hello, world!", &Some(bob_key_copy));
        let algorithm = sealed_alice_key
            .to_secret_asymmetric_byte_algorithm(Some(unsealed_bob_key), Some(get_soan()))
            .await
            .unwrap();
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap(),);
    }

    /// SECRET ASYMMETRIC KEY - BUILDER \\\
    #[test]
    fn test_sodiumoxidesecretasymmetrickeybuilder_build_valid() {
        let sosakb = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {};
        let (_, sk) = box_::gen_keypair();
        let key = sosakb.build(Some(sk.as_ref())).unwrap();
        assert_eq!(key.secret_key.as_ref(), sk.as_ref());
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidesecretasymmetrickeybuilder_build_invalid() {
        let sosakb = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {};
        let _ = sosakb.build(Some(b"bla")).unwrap();
    }

    #[test]
    fn test_sodiumoxidesecretasymmetrickeybuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Asymmetric(
            AsymmetricKeyBuilder::Secret(SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(
                SodiumOxideCurve25519SecretAsymmetricKeyBuilder {},
            )),
        )));
        let sosakb: SodiumOxideCurve25519SecretAsymmetricKeyBuilder = tbc.try_into().unwrap();
        let key = SodiumOxideCurve25519SecretAsymmetricKey::new();
        sosakb.build(Some(key.secret_key.as_ref())).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidesecretasymmetrickeybuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {})));
        let _: SodiumOxideCurve25519SecretAsymmetricKeyBuilder = tbc.try_into().unwrap();
    }

    /// SECRET ASYMMETRIC KEY - SEAL AND UNSEAL ///
    #[test]
    fn test_seal_secretasymmetrickey_with_non_referenced_key() {
        let plaintext = "hello, world!".into();
        let sosak = get_sosak();
        let (cipher_source, _) = sosak.seal(&plaintext, None, Some(&get_soan())).unwrap();
        assert_eq!(
            get_sosak_ciphertext(b"hello, world!", &None),
            cipher_source.get().unwrap().to_vec(),
        );
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_secretasymmetrickey_unseal_with_invalid_bytes() {
        let sosak = get_sosak();
        let ciphertext = "bla".into();
        let _ = sosak.unseal(&ciphertext, None, &get_soan()).unwrap();
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_secretasymmetrickey_unseal_with_invalid_nonce() {
        let sosak = get_sosak();
        let ciphertext = get_sosak_ciphertext(b"hello, world!", &None);
        let _ = sosak
            .unseal(
                &ciphertext.as_slice().into(),
                None,
                &SodiumOxideAsymmetricNonce {
                    nonce: box_::gen_nonce(),
                },
            )
            .unwrap();
    }

    #[test]
    fn test_secretasymmetrickey_to_index() {
        let index = SodiumOxideCurve25519SecretAsymmetricKey::get_index();
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
                "t": "SodiumOxideCurve25519"
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
        let sosak = SodiumOxideCurve25519SecretAsymmetricKey::new();
        let builder = sosak.builder();
        let key_bytes = sosak.secret_key.as_ref();
        let built_key = builder.build(Some(key_bytes)).unwrap();
        assert_eq!(built_key.secret_key.as_ref(), sosak.secret_key.as_ref());
    }

    #[test]
    fn test_secretasymmetrickey_new() {
        let sosak = SodiumOxideCurve25519SecretAsymmetricKey::new();
        assert!(!sosak.secret_key.as_ref().is_empty());
    }

    ///////////////////////////////////
    /// PUBLIC ASYMMETRIC KEY TESTS ///
    ///////////////////////////////////

    /// PUBLIC ASYMMETRIC BYTE ALGORITHM - SEAL ///
    #[tokio::test]
    async fn test_seal_publicasymmetricbytealgorithm_with_unsealed_key() {
        let data = Data::String("hello, world!".to_owned());
        let (alice_public_key, _) = get_sopak();
        let unsealed_alice_public_key = alice_public_key
            .to_unsealed_entry(".alicepublickey.".to_owned())
            .unwrap();
        let bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .to_unsealed_entry(".bobsecretkey.".to_owned())
            .unwrap();
        let bob_key_bytes = bob_key.resolve().await.unwrap().byte_source();
        let algorithm = unsealed_alice_public_key
            .to_public_asymmetric_byte_algorithm(bob_key, Some(get_soan()))
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        let bob_key_copy = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sopak_ciphertext(b"hello, world!", Some(&bob_key_copy))
        );
    }

    #[tokio::test]
    async fn test_seal_publicasymmetricbytealgorithm_with_referenced_key() {
        let data = Data::String("hello, world!".to_owned());
        let (alice_public_key, _) = get_sopak();
        let unsealed_alice_public_key = alice_public_key
            .to_unsealed_entry(".alicepublickey.".to_owned())
            .unwrap();
        let unsealed_bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .to_unsealed_entry(".bobsecretkey.".to_owned())
            .unwrap();
        let bob_key_bytes = unsealed_bob_key.resolve().await.unwrap().byte_source();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideCurve25519PublicAsymmetricKey>()
            .withf(|path| {
                path == ".alicepublickey."
            })
            .return_once(move |_| Ok(unsealed_alice_public_key));
        let (alice_public_key, _) = get_sopak();
        let ref_alice_public_key = alice_public_key
            .to_ref_entry(".alicepublickey.".to_owned(), storer)
            .unwrap();
        let algorithm = ref_alice_public_key
            .to_public_asymmetric_byte_algorithm(unsealed_bob_key, Some(get_soan()))
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        let bob_key_copy = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sopak_ciphertext(b"hello, world!", Some(&bob_key_copy))
        );
    }

    #[tokio::test]
    async fn test_seal_publicasymmetricbytealgorithm_with_sealed_key_with_unsealed_decryption_key()
    {
        let data = Data::String("hello, world!".to_owned());
        let alice_decryption_key = get_sosk()
            .to_unsealed_entry(".alicedecryptionkey.".to_owned())
            .unwrap();
        let alice_decryption_algorithm = alice_decryption_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let (alice_public_key, _) = get_sopak();
        let sealed_alice_public_key = alice_public_key
            .to_sealed_entry(".alicepublickey.".to_owned(), alice_decryption_algorithm)
            .await
            .unwrap();
        let bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .to_unsealed_entry(".bobsecretkey.".to_owned())
            .unwrap();
        let bob_key_bytes = bob_key.resolve().await.unwrap().byte_source();
        let algorithm = sealed_alice_public_key
            .to_public_asymmetric_byte_algorithm(bob_key, Some(get_soan()))
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        let bob_key_copy = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sopak_ciphertext(b"hello, world!", Some(&bob_key_copy))
        );
    }

    #[tokio::test]
    async fn test_seal_publicasymmetricbytealgorithm_with_sealed_key_with_referenced_decryption_key(
    ) {
        let data = Data::String("hello, world!".to_owned());
        let unsealed_alice_decryption_key = get_sosk()
            .to_unsealed_entry(".alicedecryptionkey.".to_owned())
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideSymmetricKey>()
            .withf(|path| {
                path == ".alicedecryptionkey."
            })
            .return_once(move |_| Ok(unsealed_alice_decryption_key));
        let ref_alice_decryption_key = get_sosk()
            .to_ref_entry(".alicedecryptionkey.".to_owned(), storer)
            .unwrap();
        let alice_decryption_algorithm = ref_alice_decryption_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let (alice_public_key, _) = get_sopak();
        let sealed_alice_public_key = alice_public_key
            .to_sealed_entry(".alicepublickey.".to_owned(), alice_decryption_algorithm)
            .await
            .unwrap();
        let unsealed_bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .to_unsealed_entry(".bobsecretkey.".to_owned())
            .unwrap();
        let bob_key_bytes = unsealed_bob_key.resolve().await.unwrap().byte_source();
        let algorithm = sealed_alice_public_key
            .to_public_asymmetric_byte_algorithm(unsealed_bob_key, Some(get_soan()))
            .await
            .unwrap();
        let ciphertext = algorithm.seal(&data.byte_source()).await.unwrap();
        let bob_key_copy = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        assert_eq!(
            ciphertext.get().unwrap(),
            get_sopak_ciphertext(b"hello, world!", Some(&bob_key_copy))
        );
    }

    /// PUBLIC ASYMMETRIC BYTE ALGORITHM - UNSEAL ///
    #[tokio::test]
    async fn test_unseal_publicasymmetricbytealgorithm_with_unsealed_key() {
        let data = Data::String("hello, world!".to_owned());
        let (alice_public_key, _) = get_sopak();
        let unsealed_alice_public_key = alice_public_key
            .to_unsealed_entry(".alicepublickey.".to_owned())
            .unwrap();
        let bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .to_unsealed_entry(".bobsecretkey.".to_owned())
            .unwrap();
        let bob_key_bytes = bob_key.resolve().await.unwrap().byte_source();
        let bob_key_copy = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        let ciphertext = get_sopak_ciphertext(b"hello, world!", Some(&bob_key_copy));
        let algorithm = unsealed_alice_public_key
            .to_public_asymmetric_byte_algorithm(bob_key, Some(get_soan()))
            .await
            .unwrap();
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap());
    }

    #[tokio::test]
    async fn test_unseal_publicasymmetricbytealgorithm_with_referenced_key() {
        let data = Data::String("hello, world!".to_owned());
        let (alice_public_key, _) = get_sopak();
        let unsealed_alice_public_key = alice_public_key
            .to_unsealed_entry(".alicepublickey.".to_owned())
            .unwrap();
        let unsealed_bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .to_unsealed_entry(".bobsecretkey.".to_owned())
            .unwrap();
        let bob_key_bytes = unsealed_bob_key.resolve().await.unwrap().byte_source();
        let bob_key_copy = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideCurve25519PublicAsymmetricKey>()
            .withf(|path| {
                path == ".alicepublickey."
            })
            .return_once(move |_| Ok(unsealed_alice_public_key));
        let (alice_public_key, _) = get_sopak();
        let ref_alice_public_key = alice_public_key
            .to_ref_entry(".alicepublickey.".to_owned(), storer)
            .unwrap();
        let ciphertext = get_sopak_ciphertext(b"hello, world!", Some(&bob_key_copy));
        let algorithm = ref_alice_public_key
            .to_public_asymmetric_byte_algorithm(unsealed_bob_key, Some(get_soan()))
            .await
            .unwrap();
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap());
    }

    #[tokio::test]
    async fn test_unseal_publicasymmetricbytealgorithm_with_sealed_key_with_unsealed_decryption_key(
    ) {
        let data = Data::String("hello, world!".to_owned());
        let alice_decryption_key = get_sosk()
            .to_unsealed_entry(".alicedecryptionkey.".to_owned())
            .unwrap();
        let alice_decryption_algorithm = alice_decryption_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let (alice_public_key, _) = get_sopak();
        let sealed_alice_public_key = alice_public_key
            .to_sealed_entry(".alicepublickey.".to_owned(), alice_decryption_algorithm)
            .await
            .unwrap();
        let bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .to_unsealed_entry(".bobsecretkey.".to_owned())
            .unwrap();
        let bob_key_bytes = bob_key.resolve().await.unwrap().byte_source();
        let bob_key_copy = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        let ciphertext = get_sopak_ciphertext(b"hello, world!", Some(&bob_key_copy));
        let algorithm = sealed_alice_public_key
            .to_public_asymmetric_byte_algorithm(bob_key, Some(get_soan()))
            .await
            .unwrap();
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap());
    }

    #[tokio::test]
    async fn test_unseal_publicasymmetricbytealgorithm_with_sealed_key_with_referenced_decryption_key(
    ) {
        let data = Data::String("hello, world!".to_owned());
        let unsealed_alice_decryption_key = get_sosk()
            .to_unsealed_entry(".alicedecryptionkey.".to_owned())
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_private_get::<SodiumOxideSymmetricKey>()
            .withf(|path| {
                path == ".alicedecryptionkey."
            })
            .return_once(move |_| Ok(unsealed_alice_decryption_key));
        let ref_alice_decryption_key = get_sosk()
            .to_ref_entry(".alicedecryptionkey.".to_owned(), storer)
            .unwrap();
        let alice_decryption_algorithm = ref_alice_decryption_key
            .to_symmetric_byte_algorithm(Some(get_sosn()))
            .await
            .unwrap();
        let (alice_public_key, _) = get_sopak();
        let sealed_alice_key = alice_public_key
            .to_sealed_entry(".alicepublickey.".to_owned(), alice_decryption_algorithm)
            .await
            .unwrap();
        let unsealed_bob_key = SodiumOxideCurve25519SecretAsymmetricKey::new()
            .to_unsealed_entry(".bobsecretkey.".to_owned())
            .unwrap();
        let bob_key_bytes = unsealed_bob_key.resolve().await.unwrap().byte_source();
        let bob_key_copy = SodiumOxideCurve25519SecretAsymmetricKeyBuilder {}
            .build(Some(bob_key_bytes.get().unwrap()))
            .unwrap();
        let ciphertext = get_sopak_ciphertext(b"hello, world!", Some(&bob_key_copy));
        let algorithm = sealed_alice_key
            .to_public_asymmetric_byte_algorithm(unsealed_bob_key, Some(get_soan()))
            .await
            .unwrap();
        let plaintext = algorithm
            .unseal(&ByteSource::Vector(
                AsRef::<[u8]>::as_ref(&ciphertext).into(),
            ))
            .await
            .unwrap();
        assert_eq!(data.byte_source().get().unwrap(), plaintext.get().unwrap(),);
    }

    /// PUBLIC ASYMMETRIC KEY - BUILDER ///
    #[test]
    fn test_sodiumoxidepublicasymmetrickeybuilder_build_valid() {
        let sopakb = SodiumOxideCurve25519PublicAsymmetricKeyBuilder {};
        let (_, sk) = box_::gen_keypair();
        let key = sopakb.build(Some(sk.as_ref())).unwrap();
        assert_eq!(key.public_key.as_ref(), sk.as_ref());
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidepublicasymmetrickeybuilder_build_invalid() {
        let sopakb = SodiumOxideCurve25519PublicAsymmetricKeyBuilder {};
        let _ = sopakb.build(Some(b"bla")).unwrap();
    }

    #[test]
    fn test_sodiumoxidepublicasymmetrickeybuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Asymmetric(
            AsymmetricKeyBuilder::Public(PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(
                SodiumOxideCurve25519PublicAsymmetricKeyBuilder {},
            )),
        )));
        let sopakb: SodiumOxideCurve25519PublicAsymmetricKeyBuilder = tbc.try_into().unwrap();
        let (public_key, _) = SodiumOxideCurve25519PublicAsymmetricKey::new();
        sopakb.build(Some(public_key.public_key.as_ref())).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxidepublicasymmetrickeybuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {})));
        let _: SodiumOxideCurve25519PublicAsymmetricKeyBuilder = tbc.try_into().unwrap();
    }

    /// PUBLIC ASYMMETRIC KEY - SEAL AND UNSEAL ///
    #[test]
    fn test_seal_publicasymmetrickey_with_non_referenced_key() {
        let plaintext = "hello, world!".into();
        let (sopak, sosak) = get_sopak();
        let (cipher_source, _) = sopak.seal(&plaintext, &sosak, Some(&get_soan())).unwrap();
        assert_eq!(
            get_sopak_ciphertext(b"hello, world!", None),
            cipher_source.get().unwrap().to_vec(),
        );
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_publicasymmetrickey_unseal_with_invalid_bytes() {
        let (sopak, sosak) = get_sopak();
        let ciphertext = "bla".into();
        let _ = sopak.unseal(&ciphertext, &sosak, &get_soan()).unwrap();
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_publicasymmetrickey_unseal_with_invalid_nonce() {
        let (sopak, sosak) = get_sopak();
        let ciphertext = get_sopak_ciphertext(b"hello, world!", None);
        let _ = sopak
            .unseal(
                &ciphertext.as_slice().into(),
                &sosak,
                &SodiumOxideAsymmetricNonce {
                    nonce: box_::gen_nonce(),
                },
            )
            .unwrap();
    }

    #[test]
    fn test_publicasymmetrickey_to_index() {
        let index = SodiumOxideCurve25519PublicAsymmetricKey::get_index();
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
                "t": "SodiumOxideCurve25519"
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
        let (sopak, _) = SodiumOxideCurve25519PublicAsymmetricKey::new();
        let builder = sopak.builder();
        let key_bytes = sopak.public_key.as_ref();
        let built_key = builder.build(Some(key_bytes)).unwrap();
        assert_eq!(built_key.public_key.as_ref(), sopak.public_key.as_ref());
    }

    #[test]
    fn test_publicasymmetrickey_new() {
        let (sopak, _) = SodiumOxideCurve25519PublicAsymmetricKey::new();
        assert!(!sopak.public_key.as_ref().is_empty());
    }
}
