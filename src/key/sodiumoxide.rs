use crate::{
    AsymmetricKeyBuilder, Builder, ByteSealable, ByteSource, ByteUnsealable, CryptoError,
    EntryPath, HasBuilder, HasIndex, KeyBuilder, PublicAsymmetricKeyBuilder, Sealable,
    SecretAsymmetricKeyBuilder, States, Storer, SymmetricKeyBuilder, SymmetricSealer, TypeBuilder,
    TypeBuilderContainer, Unsealable, VectorByteSource,
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
    pub source: ByteSource,
    pub key: Box<States>,
    pub nonce: ExternalSodiumOxideSymmetricNonce,
}

#[async_trait]
impl Sealable for SodiumOxideSymmetricKeySealable {
    async fn seal<T: Storer>(self, storer: T) -> Result<ByteUnsealable, CryptoError> {
        let stateful_key = *self.key.clone();
        let key = storer
            .resolve::<SodiumOxideSymmetricKey>(*self.key)
            .await
            .map_err(|e| CryptoError::StorageError { source: e })?;
        let mut unsealable = key.seal(self.source, None)?;
        unsealable.key = Box::new(stateful_key);
        Ok(ByteUnsealable::SodiumOxideSymmetricKey(unsealable))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKeyUnsealable {
    pub source: ByteSource,
    pub key: Box<States>,
    pub nonce: ExternalSodiumOxideSymmetricNonce,
}

#[async_trait]
impl Unsealable for SodiumOxideSymmetricKeyUnsealable {
    async fn unseal<S: Storer>(self, storer: S) -> Result<ByteSealable, CryptoError> {
        let stateful_key = *self.key.clone();
        let key = storer
            .resolve::<SodiumOxideSymmetricKey>(*self.key)
            .await
            .map_err(|e| CryptoError::StorageError { source: e })?;
        let ciphertext = self.source.get()?;
        let plaintext = key.unseal(ciphertext, &self.nonce)?;
        Ok(ByteSealable::SodiumOxideSymmetricKey(
            SodiumOxideSymmetricKeySealable {
                source: ByteSource::Vector(VectorByteSource::new(plaintext.as_ref())),
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

    fn seal(
        &self,
        plaintext: ByteSource,
        key_path: Option<EntryPath>,
    ) -> Result<Self::SealedOutput, CryptoError> {
        let nonce = secretbox::gen_nonce();
        let plaintext = plaintext.get()?;
        let ciphertext = secretbox::seal(plaintext, &nonce, &self.key);
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
pub struct SodiumOxideSecretAsymmetricKeySealable {
    pub source: ByteSource,
    pub key: Box<States>,
    pub nonce: ExternalSodiumOxideAsymmetricNonce,
    pub public_key: Option<Box<States>>,
}

#[async_trait]
impl Sealable for SodiumOxideSecretAsymmetricKeySealable {
    async fn seal<T: Storer>(self, storer: T) -> Result<ByteUnsealable, CryptoError> {
        let stateful_key = *self.key.clone();
        let key = storer
            .resolve::<SodiumOxideSecretAsymmetricKey>(*self.key)
            .await
            .map_err(|e| CryptoError::StorageError { source: e })?;
        let public_key = match self.public_key {
            Some(public_key) => Ok(storer
                .resolve::<SodiumOxidePublicAsymmetricKey>(*public_key)
                .await
                .map_err(|e| CryptoError::StorageError { source: e })?),
            None => Ok(SodiumOxidePublicAsymmetricKey {
                key: key.key.public_key(),
            }),
        }?;
        let mut unsealable = key.seal(self.source, Some(public_key), None)?;
        unsealable.key = Box::new(stateful_key);
        Ok(ByteUnsealable::SodiumOxideSecretAsymmetricKey(unsealable))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKeyUnsealable {
    pub source: ByteSource,
    pub key: Box<States>,
    pub nonce: ExternalSodiumOxideAsymmetricNonce,
    pub public_key: Option<Box<States>>,
}

#[async_trait]
impl Unsealable for SodiumOxideSecretAsymmetricKeyUnsealable {
    async fn unseal<S: Storer>(self, storer: S) -> Result<ByteSealable, CryptoError> {
        let stateful_key = *self.key.clone();
        let key = storer
            .resolve::<SodiumOxideSecretAsymmetricKey>(*self.key)
            .await
            .map_err(|e| CryptoError::StorageError { source: e })?;
        let public_key = match self.public_key {
            Some(public_key) => Ok(storer
                .resolve::<SodiumOxidePublicAsymmetricKey>(*public_key)
                .await
                .map_err(|e| CryptoError::StorageError { source: e })?),
            None => Ok(SodiumOxidePublicAsymmetricKey {
                key: key.key.public_key(),
            }),
        }?;
        let precomputed_key = box_::precompute(&public_key.key, &key.key);
        let ciphertext = self.source.get()?;
        let plaintext = box_::open_precomputed(ciphertext, &self.nonce, &precomputed_key)
            .map_err(|_| CryptoError::CiphertextFailedVerification)?;
        let public_key = Box::new(States::Unsealed {
            builder: public_key.builder().into(),
            bytes: ByteSource::Vector(VectorByteSource::new(public_key.key.as_ref())),
        });
        Ok(ByteSealable::SodiumOxideSecretAsymmetricKey(
            SodiumOxideSecretAsymmetricKeySealable {
                source: ByteSource::Vector(VectorByteSource::new(plaintext.as_ref())),
                key: Box::new(stateful_key),
                nonce: self.nonce,
                public_key: Some(public_key),
            },
        ))
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
            key: ExternalSodiumOxideSecretAsymmetricKey::from_slice(&bytes).ok_or(
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
        SodiumOxideSecretAsymmetricKey { key }
    }

    fn seal(
        &self,
        plaintext: ByteSource,
        public_key: Option<SodiumOxidePublicAsymmetricKey>,
        key_path: Option<EntryPath>,
    ) -> Result<SodiumOxideSecretAsymmetricKeyUnsealable, CryptoError> {
        let nonce = box_::gen_nonce();
        let plaintext = plaintext.get()?;
        let public_key = match public_key {
            Some(sopak) => sopak,
            None => SodiumOxidePublicAsymmetricKey {
                key: self.key.public_key(),
            },
        };
        let precomputed_key = box_::precompute(&public_key.key, &self.key);
        let ciphertext = box_::seal_precomputed(plaintext, &nonce, &precomputed_key);
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
        let public_key = Box::new(States::Unsealed {
            builder: public_key.builder().into(),
            bytes: ByteSource::Vector(VectorByteSource::new(self.key.as_ref())),
        });
        Ok(SodiumOxideSecretAsymmetricKeyUnsealable {
            source: ByteSource::Vector(VectorByteSource::new(ciphertext.as_ref())),
            key,
            nonce,
            public_key: Some(public_key),
        })
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
            key: ExternalSodiumOxidePublicAsymmetricKey::from_slice(&bytes).ok_or(
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

#[cfg(test)]
mod tests {
    use super::{
        SodiumOxideSymmetricKey, SodiumOxideSymmetricKeyBuilder, SodiumOxideSymmetricKeySealable,
    };
    use crate::{
        storage::tests::MockStorer, BoolDataBuilder, Builder, ByteSource, DataBuilder, Entry,
        HasBuilder, HasIndex, KeyBuilder, Sealable, States, StringDataBuilder, SymmetricKeyBuilder,
        SymmetricSealer, TypeBuilder, TypeBuilderContainer, Unsealable, VectorByteSource,
    };
    use mongodb::bson::{self, Document};
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    #[tokio::test]
    async fn test_seal_symmetrickeysealable_with_unsealed_key() {
        let source = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let raw_key = SodiumOxideSymmetricKey::new();
        let key = States::Unsealed {
            builder: TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(
                raw_key.builder(),
            ))),
            bytes: ByteSource::Vector(VectorByteSource::new(raw_key.key.as_ref())),
        };
        let nonce = secretbox::gen_nonce();
        let sosks = SodiumOxideSymmetricKeySealable {
            source,
            key: Box::new(key),
            nonce,
        };
        let storer = MockStorer::new();
        let _ = sosks.seal(storer).await.unwrap();
    }

    #[tokio::test]
    async fn test_seal_symmetrickeysealable_with_referenced_key() {
        let source = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let key_ref = States::Referenced {
            builder: TypeBuilder::Key(KeyBuilder::Symmetric(SymmetricKeyBuilder::SodiumOxide(
                SodiumOxideSymmetricKeyBuilder {},
            ))),
            path: ".keys.somePath".to_owned(),
        };
        let nonce = secretbox::gen_nonce();
        let sosks = SodiumOxideSymmetricKeySealable {
            source,
            key: Box::new(key_ref),
            nonce,
        };
        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SodiumOxideSymmetricKey>()
            .withf(|path: &str, index: &Option<Document>| {
                path == ".keys.somePath" && *index == SodiumOxideSymmetricKey::get_index()
            })
            .returning(|path, _| {
                let raw_key = SodiumOxideSymmetricKey::new();
                let key_unsealed = States::Unsealed {
                    builder: TypeBuilder::Key(KeyBuilder::Symmetric(
                        SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
                    )),
                    bytes: ByteSource::Vector(VectorByteSource::new(raw_key.key.as_ref())),
                };

                Ok(Entry {
                    path: path.to_owned(),
                    value: key_unsealed,
                })
            });
        let _ = sosks.seal(storer).await.unwrap();
    }

    #[tokio::test]
    async fn test_unseal_symmetrickeyunsealable_with_unsealed_key() {
        let source = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let raw_key = SodiumOxideSymmetricKey::new();
        let sosku = raw_key.seal(source, None).unwrap();
        let storer = MockStorer::new();
        let bs = sosku.unseal(storer).await.unwrap();
        let source = bs.get_source();
        let sdb = StringDataBuilder {};
        let d = sdb.build(source.get().unwrap()).unwrap();
        assert_eq!(d.to_string(), "hello, world!".to_owned());
    }

    #[tokio::test]
    async fn test_unseal_symmetrickeyunsealable_with_referenced_key() {
        let source = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let raw_key = SodiumOxideSymmetricKey::new();
        let key_bytes = raw_key.key.as_ref().to_vec();
        let sosku = raw_key
            .seal(source, Some(".keys.somePath".to_owned()))
            .unwrap();
        let mut storer = MockStorer::new();
        storer
            .expect_get_indexed::<SodiumOxideSymmetricKey>()
            .withf(|path: &str, index: &Option<Document>| {
                path == ".keys.somePath" && *index == SodiumOxideSymmetricKey::get_index()
            })
            .returning(move |path, _| {
                let key_unsealed = States::Unsealed {
                    builder: TypeBuilder::Key(KeyBuilder::Symmetric(
                        SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
                    )),
                    bytes: ByteSource::Vector(VectorByteSource::new(key_bytes.as_ref())),
                };

                Ok(Entry {
                    path: path.to_owned(),
                    value: key_unsealed,
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
        let sosk = SodiumOxideSymmetricKey::new();
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let unsealable = sosk.seal(plaintext, None).unwrap();
        let unsealed_bytes = sosk
            .unseal(unsealable.source.get().unwrap(), &unsealable.nonce)
            .unwrap();
        match *unsealable.key {
            States::Unsealed {
                builder: _,
                bytes: _,
            } => (),
            _ => panic!("Key used for unsealable should have been unsealed"),
        };
        assert_eq!(
            "hello, world!".to_owned(),
            String::from_utf8(unsealed_bytes).unwrap()
        );
    }

    #[test]
    fn test_seal_symmetrickey_with_referenced_key() {
        let sosk = SodiumOxideSymmetricKey::new();
        let plaintext = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let unsealable = sosk
            .seal(plaintext, Some(".keys.somePath.".to_owned()))
            .unwrap();
        let unsealed_bytes = sosk
            .unseal(unsealable.source.get().unwrap(), &unsealable.nonce)
            .unwrap();
        match *unsealable.key {
            States::Referenced { builder: _, path } => {
                assert_eq!(path, ".keys.somePath.".to_owned())
            }
            _ => panic!("Key used for unsealable should have been unsealed"),
        };
        assert_eq!(
            "hello, world!".to_owned(),
            String::from_utf8(unsealed_bytes).unwrap()
        );
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

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_symmetrickey_unseal_with_invalid_bytes() {
        let sosk = SodiumOxideSymmetricKey::new();
        let ciphertext = b"bla";
        let _ = sosk
            .unseal(ciphertext, &sodiumoxide::crypto::secretbox::gen_nonce())
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "CiphertextFailedVerification")]
    fn test_symmetrickey_unseal_with_invalid_nonce() {
        let sosk = SodiumOxideSymmetricKey::new();
        let bytes = ByteSource::Vector(VectorByteSource::new(b"hello, world!"));
        let unsealable = sosk.seal(bytes, None).unwrap();
        let _ = sosk
            .unseal(
                unsealable.source.get().unwrap(),
                &sodiumoxide::crypto::secretbox::gen_nonce(),
            )
            .unwrap();
    }
}
