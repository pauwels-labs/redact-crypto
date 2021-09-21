use crate::{AsymmetricKeyBuilder, Builder, ByteSource, CryptoError, HasAlgorithmIdentifier, HasBuilder, HasByteSource, HasIndex, HasPublicKey, KeyBuilder, PublicAsymmetricKeyBuilder, SecretAsymmetricKeyBuilder, Signer, StorableType, TypeBuilder, TypeBuilderContainer, Verifier};
use mongodb::bson::{self, Document};
use once_cell::sync::OnceCell;
use ring::{
    rand,
    signature::{self, Ed25519KeyPair as ExternalEd25519KeyPair, KeyPair,},
};
use serde::{Deserialize, Serialize};
use spki::AlgorithmIdentifier;
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
                secret_key: OnceCell::new(),
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

#[derive(Debug)]
pub struct RingEd25519SecretAsymmetricKey {
    secret_key: OnceCell<ExternalEd25519KeyPair>,
    pkcs8_doc: ByteSource,
}

impl StorableType for RingEd25519SecretAsymmetricKey {}

impl Signer for RingEd25519SecretAsymmetricKey {
    fn sign(&self, bytes: ByteSource) -> Result<ByteSource, CryptoError> {
        Ok(self.get_secret_key()?.sign(bytes.get()?).as_ref().into())
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
        Ok(RingEd25519SecretAsymmetricKey {
            secret_key: OnceCell::new(),
            pkcs8_doc: pkcs8_doc.as_ref().into(),
        })
    }

    fn get_secret_key(&self) -> Result<&ExternalEd25519KeyPair, CryptoError> {
        self.secret_key.get_or_try_init(|| {
            ExternalEd25519KeyPair::from_pkcs8(
                self.pkcs8_doc
                    .get()
                    .map_err(|e| -> CryptoError { e.into() })?,
            )
            .map_err(|e| CryptoError::InternalError {
                source: Box::new(e),
            })
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

#[derive(Debug)]
pub struct RingEd25519PublicAsymmetricKey {
    pub public_key: Vec<u8>,
}

impl Verifier for RingEd25519PublicAsymmetricKey {
    fn verify(&self, msg: ByteSource, signature: ByteSource) -> Result<(), CryptoError> {
        let peer_public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, self.public_key.clone());
        let verification_result = peer_public_key
            .verify(msg.get().unwrap(), signature.get().unwrap());

        match verification_result {
            Ok(_) => Ok(()),
            Err(_e) => Err(CryptoError::BadSignature)
        }
    }
}

impl StorableType for RingEd25519PublicAsymmetricKey {}

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

impl HasAlgorithmIdentifier for RingEd25519PublicAsymmetricKey {
    fn algorithm_identifier<'a>(&self) -> AlgorithmIdentifier<'a> {
        AlgorithmIdentifier {
            oid: spki::ObjectIdentifier::new("1.3.101.112"),
            parameters: None,
        }
    }
}

impl RingEd25519PublicAsymmetricKey {
    pub fn new() -> Result<(Self, RingEd25519SecretAsymmetricKey), CryptoError> {
        let secret_key = RingEd25519SecretAsymmetricKey::new()?;
        let public_key = secret_key.get_secret_key()?.public_key().as_ref().to_vec();
        Ok((RingEd25519PublicAsymmetricKey { public_key }, secret_key))
    }
}

impl HasPublicKey for RingEd25519SecretAsymmetricKey {
    type PublicKey = RingEd25519PublicAsymmetricKey;

    fn public_key(&self) -> Result<Self::PublicKey, CryptoError> {
        Ok(RingEd25519PublicAsymmetricKey {
            public_key: self.get_secret_key()?.public_key().as_ref().to_vec(),
        })
    }
}

impl HasAlgorithmIdentifier for RingEd25519SecretAsymmetricKey {
    fn algorithm_identifier<'a>(&self) -> AlgorithmIdentifier<'a> {
        AlgorithmIdentifier {
            oid: spki::ObjectIdentifier::new("1.3.101.112"),
            parameters: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::key::ring::{RingEd25519PublicAsymmetricKeyBuilder, RingEd25519PublicAsymmetricKey};
    use crate::{Builder, ByteSource, VectorByteSource, Verifier};

    #[test]
    fn test_ringed25519publicasymmetrickey_verify() {
        let public_key_base64 = "gSU9HQSz3Z030COosboySzkMfrBXpOmoXH3wdvReuGA=";
        let rpak = RingEd25519PublicAsymmetricKeyBuilder {};
        let public_key: RingEd25519PublicAsymmetricKey = rpak
            .build(
                Some(base64::decode(public_key_base64).unwrap().as_ref())
            ).unwrap();

        let message = ByteSource::Vector(
            VectorByteSource::new(
                Some("abc".as_ref())
            )
        );
        let signature = ByteSource::Vector(
            VectorByteSource::new(
                Some(base64::decode("JixVA5XA4+fH5PE9Czk1yApf8f3oRCcwpB5pzMdVOBgvbWzPNv4h+nulKVvCkANYWX1iNticuX5eNwpx8HpdBw==")
                    .unwrap()
                    .as_ref())
            )
        );
        public_key.verify(message, signature).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_ringed25519publicasymmetrickey_verify_with_different_message() {
        let public_key_base64 = "gSU9HQSz3Z030COosboySzkMfrBXpOmoXH3wdvReuGA=";
        let rpak = RingEd25519PublicAsymmetricKeyBuilder {};
        let public_key: RingEd25519PublicAsymmetricKey = rpak
            .build(
                Some(base64::decode(public_key_base64).unwrap().as_ref())
            ).unwrap();

        let message = ByteSource::Vector(
            VectorByteSource::new(
                Some("1233".as_ref()) // different message than signature
            )
        );
        let signature = ByteSource::Vector(
            VectorByteSource::new(
                Some(base64::decode("JixVA5XA4+fH5PE9Czk1yApf8f3oRCcwpB5pzMdVOBgvbWzPNv4h+nulKVvCkANYWX1iNticuX5eNwpx8HpdBw==")
                    .unwrap()
                    .as_ref())
            )
        );
        public_key.verify(message, signature).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_sodiumoxideed25519publicasymmetrickey_verify_with_invalid_signature() {
        let (public_key, _) = RingEd25519PublicAsymmetricKey::new().unwrap();

        let message = ByteSource::Vector(
            VectorByteSource::new(
                Some("abc".as_ref()) // different message than signature
            )
        );
        let signature = ByteSource::Vector(
            VectorByteSource::new(
                Some(base64::decode("JixVA5XA4+fH5PE9Czk1yApf8f3oRCcwpB5pzMdVOBgvbWzPNv4h+nulKVvCkANYWX1iNticuX5eNwpx8HpdBw==")
                    .unwrap()
                    .as_ref())
            )
        );
        public_key.verify(message, signature).unwrap();
    }
}