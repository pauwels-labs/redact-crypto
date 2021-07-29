use crate::{
    nonce::sodiumoxide::{SodiumOxideAsymmetricNonce, SodiumOxideSymmetricNonce},
    AsymmetricKeyBuilder, Builder, ByteSource, ByteUnsealable, CryptoError, HasBuilder,
    HasByteSource, HasIndex, HasPublicKey, KeyBuilder, PublicAsymmetricKey,
    PublicAsymmetricKeyBuilder, PublicAsymmetricSealer, PublicAsymmetricUnsealer,
    SecretAsymmetricKey, SecretAsymmetricKeyBuilder, SecretAsymmetricSealer,
    SecretAsymmetricUnsealer, Signer, State, Storer, SymmetricKey, SymmetricKeyBuilder,
    SymmetricSealer, SymmetricUnsealer, ToState, TypeBuilder, TypeBuilderContainer, Unsealable,
    VectorByteSource,
};
use async_trait::async_trait;
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
// #[derive(Serialize, Deserialize, Debug)]
// pub struct SodiumOxideSymmetricKeySealable {
//     pub source: ByteSource,
//     pub key: Box<Entry>,
//     pub nonce: SodiumOxideSymmetricNonce,
// }

// #[async_trait]
// impl Sealable for SodiumOxideSymmetricKeySealable {
//     async fn seal<T: Storer>(self, storer: T) -> Result<ByteUnsealable, CryptoError> {
//         let key = storer
//             .resolve::<SodiumOxideSymmetricKey>(self.key.value)
//             .await?;
//         let source = key.seal(self.source, Some(&self.nonce))?;
//         let unsealable = SodiumOxideSymmetricKeyUnsealable {
//             source,
//             key: Box::new(State::Referenced {
//                     builder: key.builder().into(),
//                     path: self.key.path,
//                 },
//             ),
//             nonce: self.nonce,
//         };
//         Ok(ByteUnsealable::SodiumOxideSymmetricKey(unsealable))
//     }
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideSymmetricKeyUnsealable {
    pub source: ByteSource,
    pub key: Box<State>,
    pub nonce: SodiumOxideSymmetricNonce,
}

#[async_trait]
impl Unsealable for SodiumOxideSymmetricKeyUnsealable {
    async fn unseal<S: Storer>(self, storer: &S) -> Result<ByteSource, CryptoError> {
        let key = storer.resolve::<SodiumOxideSymmetricKey>(*self.key).await?;
        let source = key.unseal(&self.source, &self.nonce)?;
        // let sosks = SodiumOxideSymmetricKeySealable {
        //     source,
        //     key: Box::new(Entry {
        //         path: self.key.path.clone(),
        //         value: State::Referenced {
        //             builder: key.builder().into(),
        //             path: self.key.path,
        //         },
        //     }),
        //     nonce: self.nonce,
        // };
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

// #[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKey {
    pub key: ExternalSodiumOxideSymmetricKey,
}

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
        Ok((
            ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
            nonce.to_owned(),
        ))
    }

    fn take_seal<F: FnOnce(SymmetricKey) -> Result<State, CryptoError>>(
        self,
        plaintext: ByteSource,
        nonce: Option<Self::Nonce>,
        key_conversion_fn: F,
    ) -> Result<ByteUnsealable, CryptoError> {
        let (source, nonce) = self.seal(&plaintext, nonce.as_ref())?;
        let key = Box::new(key_conversion_fn(SymmetricKey::SodiumOxide(self))?);
        Ok(ByteUnsealable::SodiumOxideSymmetricKey(
            SodiumOxideSymmetricKeyUnsealable { source, key, nonce },
        ))
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
        Ok(ByteSource::Vector(VectorByteSource::new(
            plaintext.as_ref(),
        )))
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
        ByteSource::Vector(VectorByteSource::new(self.key.as_ref()))
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
// #[derive(Serialize, Deserialize, Debug)]
// pub struct SodiumOxideSecretAsymmetricKeySealable {
//     pub source: ByteSource,
//     pub secret_key: Box<State>,
//     pub nonce: SodiumOxideAsymmetricNonce,
//     pub public_key: Option<Box<State>>,
// }

// #[async_trait]
// impl Sealable for SodiumOxideSecretAsymmetricKeySealable {
//     async fn seal<T: Storer>(self, storer: T) -> Result<ByteUnsealable, CryptoError> {
//         let secret_key = storer
//             .resolve::<SodiumOxideCurve25519SecretAsymmetricKey>(self.secret_key)
//             .await?;
//         let public_key = match self.public_key {
//             Some(ref public_key) => Ok::<_, CryptoError>(Some(
//                 storer
//                     .resolve::<SodiumOxideCurve25519PublicAsymmetricKey>(*public_key)
//                     .await?,
//             )),
//             None => Ok(None),
//         }?;
//         let source = secret_key.seal(&self.source, public_key.as_ref(), Some(&self.nonce))?;
//         let unsealable = SodiumOxideSecretAsymmetricKeyUnsealable {
//             source,
//             secret_key: self.secret_key,
//             nonce: self.nonce,
//             public_key: self.public_key,
//         };
//         Ok(ByteUnsealable::SodiumOxideSecretAsymmetricKey(unsealable))
//     }
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideSecretAsymmetricKeyUnsealable {
    pub source: ByteSource,
    pub secret_key: Box<State>,
    pub nonce: SodiumOxideAsymmetricNonce,
    pub public_key: Option<Box<State>>,
}

#[async_trait]
impl Unsealable for SodiumOxideSecretAsymmetricKeyUnsealable {
    async fn unseal<S: Storer>(self, storer: &S) -> Result<ByteSource, CryptoError> {
        let secret_key = storer
            .resolve::<SodiumOxideCurve25519SecretAsymmetricKey>(*self.secret_key)
            .await?;
        let public_key = match self.public_key {
            Some(public_key) => Ok::<_, CryptoError>(Some(
                storer
                    .resolve::<SodiumOxideCurve25519PublicAsymmetricKey>(*public_key)
                    .await?,
            )),
            None => Ok(None),
        }?;
        let source = secret_key.unseal(&self.source, public_key.as_ref(), &self.nonce)?;
        // let sosaks = SodiumOxideSecretAsymmetricKeySealable {
        //     source,
        //     secret_key: self.secret_key,
        //     public_key: self.public_key,
        //     nonce: self.nonce,
        // };
        //Ok(ByteSealable::SodiumOxideSecretAsymmetricKey(sosaks))
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

pub struct SodiumOxideCurve25519SecretAsymmetricKey {
    pub secret_key: ExternalSodiumOxideCurve25519SecretAsymmetricKey,
}

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
        Ok((
            ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
            nonce.to_owned(),
        ))
    }

    fn take_seal<F: FnOnce(SecretAsymmetricKey) -> Result<State, CryptoError>>(
        self,
        plaintext: ByteSource,
        public_key: Option<Self::PublicKey>,
        nonce: Option<Self::Nonce>,
        key_conversion_fn: F,
    ) -> Result<ByteUnsealable, CryptoError> {
        let (source, nonce) = self.seal(&plaintext, public_key.as_ref(), nonce.as_ref())?;
        let public_key = match public_key {
            Some(public_key) => Some(Box::new(
                public_key.to_unsealed_state(ByteSource::Vector(VectorByteSource::new(b"")))?,
            )),
            None => None,
        };
        let secret_key = Box::new(key_conversion_fn(
            SecretAsymmetricKey::SodiumOxideCurve25519(self),
        )?);
        Ok(ByteUnsealable::SodiumOxideSecretAsymmetricKey(
            SodiumOxideSecretAsymmetricKeyUnsealable {
                source,
                secret_key,
                nonce,
                public_key,
            },
        ))
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
        Ok(ByteSource::Vector(VectorByteSource::new(
            plaintext.as_ref(),
        )))
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
        ByteSource::Vector(VectorByteSource::new(self.secret_key.as_ref()))
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
// #[derive(Serialize, Deserialize, Debug)]
// pub struct SodiumOxidePublicAsymmetricKeySealable {
//     pub source: ByteSource,
//     pub public_key: Box<State>,
//     pub nonce: SodiumOxideAsymmetricNonce,
//     pub secret_key: Box<State>,
// }

// #[async_trait]
// impl Sealable for SodiumOxidePublicAsymmetricKeySealable {
//     async fn seal<T: Storer>(self, storer: T) -> Result<ByteUnsealable, CryptoError> {
//         let secret_key_path = match *self.public_key {
//             State::Referenced {
//                 builder: _,
//                 ref path,
//             } => Some(path.clone()),
//             _ => None,
//         };
//         let secret_key = storer
//             .resolve::<SodiumOxideCurve25519SecretAsymmetricKey>(&self.secret_key)
//             .await?;
//         let public_key = storer
//             .resolve::<SodiumOxideCurve25519PublicAsymmetricKey>(&self.public_key)
//             .await?;
//         let source = public_key.seal(&self.source, &secret_key, Some(&self.nonce))?;
//         let unsealable = SodiumOxidePublicAsymmetricKeyUnsealable {
//             source,
//             secret_key: self.secret_key,
//             nonce: self.nonce,
//             public_key: self.public_key,
//         };
//         Ok(ByteUnsealable::SodiumOxidePublicAsymmetricKey(unsealable))
//     }
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxidePublicAsymmetricKeyUnsealable {
    pub source: ByteSource,
    pub public_key: Box<State>,
    pub nonce: SodiumOxideAsymmetricNonce,
    pub secret_key: Box<State>,
}

#[async_trait]
impl Unsealable for SodiumOxidePublicAsymmetricKeyUnsealable {
    async fn unseal<S: Storer>(self, storer: &S) -> Result<ByteSource, CryptoError> {
        let secret_key = storer
            .resolve::<SodiumOxideCurve25519SecretAsymmetricKey>(*self.secret_key)
            .await?;
        let public_key = storer
            .resolve::<SodiumOxideCurve25519PublicAsymmetricKey>(*self.public_key)
            .await?;
        let source = public_key.unseal(&self.source, &secret_key, &self.nonce)?;
        // let sopaks = SodiumOxidePublicAsymmetricKeySealable {
        //     source,
        //     public_key: self.public_key,
        //     nonce: self.nonce,
        //     secret_key: self.secret_key,
        // };
        // Ok(ByteSealable::SodiumOxidePublicAsymmetricKey(sopaks))
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

pub struct SodiumOxideCurve25519PublicAsymmetricKey {
    pub public_key: ExternalSodiumOxideCurve25519PublicAsymmetricKey,
}

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
        Ok((
            ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
            nonce.to_owned(),
        ))
    }

    fn take_seal<F: FnOnce(SecretAsymmetricKey) -> Result<State, CryptoError>>(
        self,
        plaintext: ByteSource,
        secret_key: Self::SecretKey,
        nonce: Option<Self::Nonce>,
        key_conversion_fn: F,
    ) -> Result<ByteUnsealable, CryptoError> {
        let (source, nonce) = self.seal(&plaintext, &secret_key, nonce.as_ref())?;
        let secret_key = Box::new(key_conversion_fn(
            SecretAsymmetricKey::SodiumOxideCurve25519(secret_key),
        )?);
        let public_key =
            Box::new(self.to_unsealed_state(ByteSource::Vector(VectorByteSource::new(b"")))?);
        Ok(ByteUnsealable::SodiumOxidePublicAsymmetricKey(
            SodiumOxidePublicAsymmetricKeyUnsealable {
                source,
                secret_key,
                nonce,
                public_key,
            },
        ))
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
        Ok(ByteSource::Vector(VectorByteSource::new(
            plaintext.as_ref(),
        )))
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
        ByteSource::Vector(VectorByteSource::new(self.public_key.as_ref()))
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
    fn public_key(&self) -> PublicAsymmetricKey {
        PublicAsymmetricKey::SodiumOxideCurve25519(SodiumOxideCurve25519PublicAsymmetricKey {
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

pub struct SodiumOxideEd25519SecretAsymmetricKey {
    pub secret_key: ExternalSodiumOxideEd25519SecretAsymmetricKey,
}

impl Signer for SodiumOxideEd25519SecretAsymmetricKey {
    fn sign(&self, bytes: ByteSource) -> Result<ByteSource, CryptoError> {
        Ok(ByteSource::Vector(VectorByteSource::new(
            sign::sign(bytes.get()?, &self.secret_key).as_ref(),
        )))
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
        ByteSource::Vector(VectorByteSource::new(self.secret_key.as_ref()))
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

pub struct SodiumOxideEd25519PublicAsymmetricKey {
    pub public_key: ExternalSodiumOxideEd25519PublicAsymmetricKey,
}

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
        ByteSource::Vector(VectorByteSource::new(self.public_key.as_ref()))
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
    fn public_key(&self) -> PublicAsymmetricKey {
        PublicAsymmetricKey::SodiumOxideEd25519(SodiumOxideEd25519PublicAsymmetricKey {
            public_key: self.secret_key.public_key(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SodiumOxideCurve25519PublicAsymmetricKey, SodiumOxideCurve25519PublicAsymmetricKeyBuilder,
        SodiumOxideCurve25519SecretAsymmetricKey, SodiumOxideCurve25519SecretAsymmetricKeyBuilder,
        SodiumOxidePublicAsymmetricKeyUnsealable, SodiumOxideSecretAsymmetricKeyUnsealable,
        SodiumOxideSymmetricKey, SodiumOxideSymmetricKeyBuilder, SodiumOxideSymmetricKeyUnsealable,
    };
    use crate::{
        nonce::sodiumoxide::{SodiumOxideAsymmetricNonce, SodiumOxideSymmetricNonce},
        storage::tests::MockStorer,
        AsymmetricKeyBuilder, BoolDataBuilder, Builder, ByteSource, ByteUnsealable, DataBuilder,
        Entry, HasBuilder, HasIndex, KeyBuilder, PublicAsymmetricKeyBuilder,
        PublicAsymmetricSealer, PublicAsymmetricUnsealer, SecretAsymmetricKeyBuilder,
        SecretAsymmetricSealer, SecretAsymmetricUnsealer, State, StringDataBuilder,
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

    fn get_unsealed_sopak() -> State {
        let (public_key, _) = get_sopak();
        State::Unsealed {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(public_key.builder()),
            ))),
            bytes: ByteSource::Vector(VectorByteSource::new(public_key.public_key.as_ref())),
        }
    }

    fn get_referenced_sopak(path: &str) -> State {
        State::Referenced {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(
                    SodiumOxideCurve25519PublicAsymmetricKeyBuilder {},
                ),
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

    // fn get_sopaks_with_unsealed_key(
    //     payload: &[u8],
    //     secret_key: Option<&SodiumOxideCurve25519SecretAsymmetricKey>,
    // ) -> SodiumOxidePublicAsymmetricKeySealable {
    //     let source = ByteSource::Vector(VectorByteSource::new(payload));
    //     let secret_key = match secret_key {
    //         Some(sk) => Box::new(State::Unsealed {
    //             builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
    //                 SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(sk.builder()),
    //             ))),
    //             bytes: ByteSource::Vector(VectorByteSource::new(sk.secret_key.as_ref())),
    //         }),
    //         None => Box::new(get_unsealed_sosak()),
    //     };

    //     SodiumOxidePublicAsymmetricKeySealable {
    //         source,
    //         public_key: Box::new(get_unsealed_sopak()),
    //         nonce: get_soan(),
    //         secret_key,
    //     }
    // }

    // fn get_sopaks_with_referenced_key(
    //     payload: &[u8],
    //     secret_key: Option<&SodiumOxideCurve25519SecretAsymmetricKey>,
    //     path: &str,
    // ) -> SodiumOxidePublicAsymmetricKeySealable {
    //     let source = ByteSource::Vector(VectorByteSource::new(payload));
    //     let secret_key = match secret_key {
    //         Some(sk) => Box::new(State::Unsealed {
    //             builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
    //                 SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(sk.builder()),
    //             ))),
    //             bytes: ByteSource::Vector(VectorByteSource::new(sk.secret_key.as_ref())),
    //         }),
    //         None => Box::new(get_unsealed_sosak()),
    //     };
    //     SodiumOxidePublicAsymmetricKeySealable {
    //         source,
    //         secret_key,
    //         nonce: get_soan(),
    //         public_key: Box::new(get_referenced_sopak(path)),
    //     }
    // }

    fn get_sopaku_with_unsealed_key(
        plaintext: &[u8],
        secret_key: Option<&SodiumOxideCurve25519SecretAsymmetricKey>,
    ) -> SodiumOxidePublicAsymmetricKeyUnsealable {
        let ciphertext = get_sopak_ciphertext(plaintext, secret_key);
        let secret_key = match secret_key {
            Some(sk) => Box::new(State::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                    SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(
                        SodiumOxideCurve25519SecretAsymmetricKeyBuilder {},
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
        secret_key: Option<&SodiumOxideCurve25519SecretAsymmetricKey>,
        path: &str,
    ) -> SodiumOxidePublicAsymmetricKeyUnsealable {
        let ciphertext = get_sopak_ciphertext(plaintext, secret_key);
        let secret_key = match secret_key {
            Some(sk) => Box::new(State::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                    SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(
                        SodiumOxideCurve25519SecretAsymmetricKeyBuilder {},
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

    fn get_unsealed_sosak() -> State {
        let key = get_sosak();
        State::Unsealed {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(key.builder()),
            ))),
            bytes: ByteSource::Vector(VectorByteSource::new(key.secret_key.as_ref())),
        }
    }

    fn get_referenced_sosak(path: &str) -> State {
        State::Referenced {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(
                    SodiumOxideCurve25519SecretAsymmetricKeyBuilder {},
                ),
            ))),
            path: path.to_owned(),
        }
    }

    fn get_sealed_sosak_with_unsealed_key() -> State {
        State::Sealed {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(
                    SodiumOxideCurve25519SecretAsymmetricKeyBuilder {},
                ),
            ))),
            unsealable: ByteUnsealable::SodiumOxideSecretAsymmetricKey(
                get_sosaku_with_unsealed_key(get_sosak().secret_key.as_ref(), None),
            ),
        }
    }

    fn get_sealed_sosak_with_referenced_key(path: &str) -> State {
        State::Sealed {
            builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::SodiumOxideCurve25519(
                    SodiumOxideCurve25519SecretAsymmetricKeyBuilder {},
                ),
            ))),
            unsealable: ByteUnsealable::SodiumOxideSecretAsymmetricKey(
                get_sosaku_with_referenced_key(get_sosak().secret_key.as_ref(), None, path),
            ),
        }
    }

    // fn get_sosaks_with_unsealed_key(
    //     payload: &[u8],
    //     public_key: Option<SodiumOxideCurve25519PublicAsymmetricKey>,
    // ) -> SodiumOxideSecretAsymmetricKeySealable {
    //     let source = ByteSource::Vector(VectorByteSource::new(payload));
    //     let public_key = match public_key {
    //         Some(pk) => Some(Box::new(State::Unsealed {
    //             builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
    //                 PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(
    //                     SodiumOxideCurve25519PublicAsymmetricKeyBuilder {},
    //                 ),
    //             ))),
    //             bytes: ByteSource::Vector(VectorByteSource::new(pk.public_key.as_ref())),
    //         })),
    //         None => None,
    //     };
    //     SodiumOxideSecretAsymmetricKeySealable {
    //         source,
    //         secret_key: Box::new(get_unsealed_sosak()),
    //         nonce: get_soan(),
    //         public_key,
    //     }
    // }

    // fn get_sosaks_with_referenced_key(
    //     payload: &[u8],
    //     public_key: Option<SodiumOxideCurve25519PublicAsymmetricKey>,
    //     path: &str,
    // ) -> SodiumOxideSecretAsymmetricKeySealable {
    //     let source = ByteSource::Vector(VectorByteSource::new(payload));
    //     let public_key = match public_key {
    //         Some(pk) => Some(Box::new(State::Unsealed {
    //             builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
    //                 PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(
    //                     SodiumOxideCurve25519PublicAsymmetricKeyBuilder {},
    //                 ),
    //             ))),
    //             bytes: ByteSource::Vector(VectorByteSource::new(pk.public_key.as_ref())),
    //         })),
    //         None => None,
    //     };
    //     SodiumOxideSecretAsymmetricKeySealable {
    //         source,
    //         secret_key: Box::new(get_referenced_sosak(path)),
    //         nonce: get_soan(),
    //         public_key,
    //     }
    // }

    fn get_sosaku_with_unsealed_key(
        plaintext: &[u8],
        public_key: Option<SodiumOxideCurve25519PublicAsymmetricKey>,
    ) -> SodiumOxideSecretAsymmetricKeyUnsealable {
        let ciphertext = get_sosak_ciphertext(plaintext, &public_key);
        let public_key = match public_key {
            Some(pk) => Some(Box::new(State::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                    PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(
                        SodiumOxideCurve25519PublicAsymmetricKeyBuilder {},
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
        public_key: Option<SodiumOxideCurve25519PublicAsymmetricKey>,
        path: &str,
    ) -> SodiumOxideSecretAsymmetricKeyUnsealable {
        let ciphertext = get_sosak_ciphertext(plaintext, &public_key);
        let public_key = match public_key {
            Some(pk) => Some(Box::new(State::Unsealed {
                builder: TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                    PublicAsymmetricKeyBuilder::SodiumOxideCurve25519(
                        SodiumOxideCurve25519PublicAsymmetricKeyBuilder {},
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

    /// Returns the key from get_sosk() wrapped in a States::Unsealed
    fn get_unsealed_sosk() -> State {
        let sosk = get_sosk();
        State::Unsealed {
            builder: TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(
                sosk.builder(),
            ))),
            bytes: ByteSource::Vector(VectorByteSource::new(sosk.key.as_ref())),
        }
    }

    /// Returns the key from get_sosk() wrapped in a States::Referenced
    fn get_referenced_sosk(path: &str) -> State {
        State::Referenced {
            builder: TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(
                SodiumOxideSymmetricKeyBuilder {},
            ))),
            path: path.to_string(),
        }
    }

    /// Returns the key from get_sosk() wrapped in a States::Sealed and decrypted
    /// by an unsealed version of the key from get_sosk()
    fn get_sealed_sosk_with_unsealed_key() -> State {
        State::Sealed {
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
    fn get_sealed_sosk_with_referenced_key(path: &str) -> State {
        State::Sealed {
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
    // fn get_sosks_with_unsealed_key(payload: &[u8]) -> SodiumOxideSymmetricKeySealable {
    //     let source = ByteSource::Vector(VectorByteSource::new(payload));
    //     SodiumOxideSymmetricKeySealable {
    //         source,
    //         key: Box::new(get_unsealed_sosk()),
    //         nonce: get_sosn(),
    //     }
    // }

    // /// Returns a sealable backed by get_referenced_sosk() with the bytes "hello, world!"
    // fn get_sosks_with_referenced_key(
    //     payload: &[u8],
    //     path: &str,
    // ) -> SodiumOxideSymmetricKeySealable {
    //     let source = ByteSource::Vector(VectorByteSource::new(payload));
    //     SodiumOxideSymmetricKeySealable {
    //         source,
    //         key: Box::new(get_referenced_sosk(path)),
    //         nonce: get_sosn(),
    //     }
    // }

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

    // #[tokio::test]
    // async fn test_seal_symmetrickeysealable_with_unsealed_key() {
    //     let sosks = get_sosks_with_unsealed_key(b"hello, world");
    //     let storer = MockStorer::new();
    //     let _ = sosks.seal(storer).await.unwrap();
    // }

    // #[tokio::test]
    // async fn test_seal_symmetrickeysealable_with_referenced_key() {
    //     let sosks = get_sosks_with_referenced_key(b"hello, world", ".path.default.");
    //     let mut storer = MockStorer::new();
    //     storer
    //         .expect_get_indexed::<SodiumOxideSymmetricKey>()
    //         .withf(|path: &str, index: &Option<Document>| {
    //             path == ".path.default." && *index == Some(bson::doc! { "c": { "builder": { "t": "Key", "c": { "t": "Symmetric", "c": { "t": "SodiumOxide" } } } } })
    //         })
    //         .returning(|path, _| {
    //             Ok(Entry {
    //                 path: path.to_owned(),
    //                 value: get_unsealed_sosk(),
    //             })
    //         });
    //     let _ = sosks.seal(storer).await.unwrap();
    // }

    #[tokio::test]
    async fn test_unseal_symmetrickeyunsealable_with_unsealed_key() {
        let sosku = get_sosku_with_unsealed_key(b"hello, world!");
        let storer = MockStorer::new();
        let source = sosku.unseal(&storer).await.unwrap();
        let sdb = StringDataBuilder {};
        let d = sdb.build(Some(source.get().unwrap())).unwrap();
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
        let source = sosku.unseal(&storer).await.unwrap();
        let sdb = StringDataBuilder {};
        let d = sdb.build(Some(source.get().unwrap())).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

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

    #[test]
    fn test_seal_symmetrickey() {
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
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
        let ciphertext = ByteSource::Vector(VectorByteSource::new(b"bla"));
        let _ = sosk.unseal(&ciphertext, &get_sosn()).unwrap();
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_symmetrickey_unseal_with_invalid_nonce() {
        let sosk = get_sosk();
        let ciphertext = get_sosk_ciphertext(b"hello, world!");
        let _ = sosk
            .unseal(
                &ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
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

    // #[tokio::test]
    // async fn test_seal_secretasymmetrickeysealable_with_unsealed_key() {
    //     let sosaks = get_sosaks_with_unsealed_key(b"hello, world!", None);
    //     let storer = MockStorer::new();
    //     let ciphertext = sosaks.seal(storer).await.unwrap();
    //     assert_eq!(
    //         ciphertext.get_source().get().unwrap(),
    //         get_sosak_ciphertext(b"hello, world!", None)
    //     );
    // }

    // #[tokio::test]
    // async fn test_seal_secretasymmetrickeysealable_with_separate_public_key() {
    //     let (other_sopak, _) = SodiumOxideCurve25519PublicAsymmetricKey::new();
    //     let sosaks = get_sosaks_with_unsealed_key(b"hello, world!", Some(other_sopak.clone()));
    //     let storer = MockStorer::new();
    //     let ciphertext = sosaks.seal(storer).await.unwrap();
    //     assert_eq!(
    //         ciphertext.get_source().get().unwrap(),
    //         get_sosak_ciphertext(b"hello, world!", Some(other_sopak))
    //     );
    // }

    // #[tokio::test]
    // async fn test_seal_secretasymmetrickeysealable_with_referenced_key() {
    //     let sosaks = get_sosaks_with_referenced_key(b"hello, world!", None, ".keys.default.");
    //     let mut storer = MockStorer::new();
    //     storer
    //         .expect_get_indexed::<SodiumOxideCurve25519SecretAsymmetricKey>()
    //         .withf(|path: &str, index: &Option<Document>| {
    //             path == ".keys.default."
    //                 && *index == SodiumOxideCurve25519SecretAsymmetricKey::get_index()
    //         })
    //         .returning(|path, _| {
    //             Ok(Entry {
    //                 path: path.to_owned(),
    //                 value: get_unsealed_sosak(),
    //             })
    //         });
    //     let ciphertext = sosaks.seal(storer).await.unwrap();
    //     assert_eq!(
    //         ciphertext.get_source().get().unwrap(),
    //         get_sosak_ciphertext(b"hello, world!", None)
    //     );
    // }

    #[tokio::test]
    async fn test_unseal_secretasymmetrickeyunsealable_with_unsealed_key() {
        let sosaku = get_sosaku_with_unsealed_key(b"hello, world!", None);
        let storer = MockStorer::new();
        let source = sosaku.unseal(&storer).await.unwrap();
        let sdb = StringDataBuilder {};
        let d = sdb.build(Some(source.get().unwrap())).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

    #[tokio::test]
    async fn test_unseal_secretasymmetrickeyunsealable_with_separate_public_key() {
        let (other_sopak, _) = SodiumOxideCurve25519PublicAsymmetricKey::new();
        let sosaku = get_sosaku_with_unsealed_key(b"hello, world!", Some(other_sopak));
        let storer = MockStorer::new();
        let ciphertext = sosaku.unseal(&storer).await.unwrap();
        assert_eq!(ciphertext.get().unwrap(), b"hello, world!",);
    }

    #[tokio::test]
    async fn test_unseal_secretasymmetrickeyunsealable_with_referenced_key() {
        let sosaku = get_sosaku_with_referenced_key(b"hello, world!", None, ".keys.default.");
        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SodiumOxideCurve25519SecretAsymmetricKey>()
            .withf(|path: &str, index: &Option<Document>| {
                path == ".keys.default."
                    && *index == SodiumOxideCurve25519SecretAsymmetricKey::get_index()
            })
            .returning(|path, _| {
                Ok(Entry {
                    path: path.to_owned(),
                    value: get_unsealed_sosak(),
                })
            });
        let source = sosaku.unseal(&storer).await.unwrap();
        let sdb = StringDataBuilder {};
        let d = sdb.build(Some(source.get().unwrap())).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

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

    #[test]
    fn test_seal_secretasymmetrickey_with_non_referenced_key() {
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
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
        let ciphertext = ByteSource::Vector(VectorByteSource::new(b"bla"));
        let _ = sosak.unseal(&ciphertext, None, &get_soan()).unwrap();
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_secretasymmetrickey_unseal_with_invalid_nonce() {
        let sosak = get_sosak();
        let ciphertext = get_sosak_ciphertext(b"hello, world!", &None);
        let _ = sosak
            .unseal(
                &ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
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
    // #[tokio::test]
    // async fn test_seal_publicasymmetrickeysealable_with_unsealed_key() {
    //     let sopaks = get_sopaks_with_unsealed_key(b"hello, world!", None);
    //     let storer = MockStorer::new();
    //     let ciphertext = sopaks.seal(storer).await.unwrap();
    //     assert_eq!(
    //         ciphertext.get_source().get().unwrap(),
    //         get_sopak_ciphertext(b"hello, world!", None)
    //     );
    // }

    // #[tokio::test]
    // async fn test_seal_publicasymmetrickeysealable_with_separate_secret_key() {
    //     let (_, other_sosak) = SodiumOxideCurve25519PublicAsymmetricKey::new();
    //     let sopaks = get_sopaks_with_unsealed_key(b"hello, world!", Some(&other_sosak));
    //     let storer = MockStorer::new();
    //     let ciphertext = sopaks.seal(storer).await.unwrap();
    //     assert_eq!(
    //         ciphertext.get_source().get().unwrap(),
    //         get_sopak_ciphertext(b"hello, world!", Some(&other_sosak))
    //     );
    // }

    // #[tokio::test]
    // async fn test_seal_publicasymmetrickeysealable_with_referenced_key() {
    //     let sopaks = get_sopaks_with_referenced_key(b"hello, world!", None, ".keys.default.");
    //     let mut storer = MockStorer::new();
    //     storer
    //         .expect_get_indexed::<SodiumOxideCurve25519PublicAsymmetricKey>()
    //         .withf(|path: &str, index: &Option<Document>| {
    //             path == ".keys.default."
    //                 && *index == SodiumOxideCurve25519PublicAsymmetricKey::get_index()
    //         })
    //         .returning(|path, _| {
    //             Ok(Entry {
    //                 path: path.to_owned(),
    //                 value: get_unsealed_sopak(),
    //             })
    //         });
    //     let ciphertext = sopaks.seal(storer).await.unwrap();
    //     assert_eq!(
    //         ciphertext.get_source().get().unwrap(),
    //         get_sopak_ciphertext(b"hello, world!", None)
    //     );
    // }

    #[tokio::test]
    async fn test_unseal_publicasymmetrickeyunsealable_with_unsealed_key() {
        let sopaku = get_sopaku_with_unsealed_key(b"hello, world!", None);
        let storer = MockStorer::new();
        let source = sopaku.unseal(&storer).await.unwrap();
        let sdb = StringDataBuilder {};
        let d = sdb.build(Some(source.get().unwrap())).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

    #[tokio::test]
    async fn test_unseal_publicasymmetrickeyunsealable_with_separate_public_key() {
        let (_, other_sosak) = SodiumOxideCurve25519PublicAsymmetricKey::new();
        let sopaku = get_sopaku_with_unsealed_key(b"hello, world!", Some(&other_sosak));
        let storer = MockStorer::new();
        let ciphertext = sopaku.unseal(&storer).await.unwrap();
        assert_eq!(ciphertext.get().unwrap(), b"hello, world!",);
    }

    #[tokio::test]
    async fn test_unseal_publicasymmetrickeyunsealable_with_referenced_key() {
        let sopaku = get_sopaku_with_referenced_key(b"hello, world!", None, ".keys.default.");
        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SodiumOxideCurve25519PublicAsymmetricKey>()
            .withf(|path: &str, index: &Option<Document>| {
                path == ".keys.default."
                    && *index == SodiumOxideCurve25519PublicAsymmetricKey::get_index()
            })
            .returning(|path, _| {
                Ok(Entry {
                    path: path.to_owned(),
                    value: get_unsealed_sopak(),
                })
            });
        let source = sopaku.unseal(&storer).await.unwrap();
        let sdb = StringDataBuilder {};
        let d = sdb.build(Some(source.get().unwrap())).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

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

    #[test]
    fn test_seal_publicasymmetrickey_with_non_referenced_key() {
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
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
        let ciphertext = ByteSource::Vector(VectorByteSource::new(b"bla"));
        let _ = sopak.unseal(&ciphertext, &sosak, &get_soan()).unwrap();
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_publicasymmetrickey_unseal_with_invalid_nonce() {
        let (sopak, sosak) = get_sopak();
        let ciphertext = get_sopak_ciphertext(b"hello, world!", None);
        let _ = sopak
            .unseal(
                &ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
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
