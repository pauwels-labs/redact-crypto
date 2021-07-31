use crate::{
    AsymmetricKeyBuilder, Builder, ByteSource, CryptoError, HasBuilder, HasByteSource, HasIndex,
    HasPublicKey, KeyBuilder, PublicAsymmetricKey, PublicAsymmetricKeyBuilder,
    SecretAsymmetricKeyBuilder, Signer, TypeBuilder, TypeBuilderContainer,
};
use mongodb::bson::{self, Document};
use ring::{
    rand,
    signature::{Ed25519KeyPair as ExternalEd25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

// SECRET SIGNING KEY \\
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct RingEd25519SecretAsymmetricKeyBuilder {}

impl TryFrom<TypeBuilderContainer> for RingEd25519SecretAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
                SecretAsymmetricKeyBuilder::RingEd25519(sopakb),
            ))) => Ok(sopakb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for RingEd25519SecretAsymmetricKeyBuilder {
    type Output = RingEd25519SecretAsymmetricKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => Ok(RingEd25519SecretAsymmetricKey {
                secret_key: ExternalEd25519KeyPair::from_pkcs8(bytes).map_err(|e| {
                    CryptoError::InternalError {
                        source: Box::new(e),
                    }
                })?,
                pkcs8_doc: bytes.into(),
            }),
            None => RingEd25519SecretAsymmetricKey::new(),
        }
    }
}

impl From<RingEd25519SecretAsymmetricKeyBuilder> for TypeBuilder {
    fn from(b: RingEd25519SecretAsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Secret(
            SecretAsymmetricKeyBuilder::RingEd25519(b),
        )))
    }
}

pub struct RingEd25519SecretAsymmetricKey {
    pub secret_key: ExternalEd25519KeyPair,
    pkcs8_doc: ByteSource,
}

impl Signer for RingEd25519SecretAsymmetricKey {
    fn sign(&self, bytes: ByteSource) -> Result<ByteSource, CryptoError> {
        Ok(self.secret_key.sign(bytes.get()?).as_ref().into())
    }
}

impl HasIndex for RingEd25519SecretAsymmetricKey {
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
        "t": "RingEd25519"
        }
        }
        }
            }
        }
            })
    }
}

impl HasBuilder for RingEd25519SecretAsymmetricKey {
    type Builder = RingEd25519SecretAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        RingEd25519SecretAsymmetricKeyBuilder {}
    }
}

impl HasByteSource for RingEd25519SecretAsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        self.pkcs8_doc.clone()
    }
}

impl RingEd25519SecretAsymmetricKey {
    pub fn new() -> Result<Self, CryptoError> {
        let rng = rand::SystemRandom::new();
        let pkcs8_doc = ExternalEd25519KeyPair::generate_pkcs8(&rng).map_err(|e| {
            CryptoError::InternalError {
                source: Box::new(e),
            }
        })?;
        let secret_key = ExternalEd25519KeyPair::from_pkcs8(pkcs8_doc.as_ref()).map_err(|e| {
            CryptoError::InternalError {
                source: Box::new(e),
            }
        })?;
        Ok(RingEd25519SecretAsymmetricKey {
            secret_key,
            pkcs8_doc: pkcs8_doc.as_ref().into(),
        })
    }
}

// PUBLIC SIGNING KEY \\
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct RingEd25519PublicAsymmetricKeyBuilder {}

impl TryFrom<TypeBuilderContainer> for RingEd25519PublicAsymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
                PublicAsymmetricKeyBuilder::RingEd25519(sopakb),
            ))) => Ok(sopakb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for RingEd25519PublicAsymmetricKeyBuilder {
    type Output = RingEd25519PublicAsymmetricKey;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => Ok(RingEd25519PublicAsymmetricKey {
                public_key: bytes.to_vec(),
            }),
            None => {
                let (pk, _) = RingEd25519PublicAsymmetricKey::new()?;
                Ok(pk)
            }
        }
    }
}

impl From<RingEd25519PublicAsymmetricKeyBuilder> for TypeBuilder {
    fn from(b: RingEd25519PublicAsymmetricKeyBuilder) -> TypeBuilder {
        TypeBuilder::Key(KeyBuilder::Asymmetric(AsymmetricKeyBuilder::Public(
            PublicAsymmetricKeyBuilder::RingEd25519(b),
        )))
    }
}

pub struct RingEd25519PublicAsymmetricKey {
    pub public_key: Vec<u8>,
}

impl HasIndex for RingEd25519PublicAsymmetricKey {
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
        "t": "RingEd25519"
        }
        }
        }
            }
        }
            })
    }
}

impl HasBuilder for RingEd25519PublicAsymmetricKey {
    type Builder = RingEd25519PublicAsymmetricKeyBuilder;

    fn builder(&self) -> Self::Builder {
        RingEd25519PublicAsymmetricKeyBuilder {}
    }
}

impl HasByteSource for RingEd25519PublicAsymmetricKey {
    fn byte_source(&self) -> ByteSource {
        self.public_key.as_slice().into()
    }
}

impl RingEd25519PublicAsymmetricKey {
    pub fn new() -> Result<(Self, RingEd25519SecretAsymmetricKey), CryptoError> {
        let secret_key = RingEd25519SecretAsymmetricKey::new()?;
        let public_key = secret_key.secret_key.public_key().as_ref().to_vec();
        Ok((RingEd25519PublicAsymmetricKey { public_key }, secret_key))
    }
}

impl HasPublicKey for RingEd25519SecretAsymmetricKey {
    fn public_key(&self) -> PublicAsymmetricKey {
        PublicAsymmetricKey::RingEd25519(RingEd25519PublicAsymmetricKey {
            public_key: self.secret_key.public_key().as_ref().to_vec(),
        })
    }
}
