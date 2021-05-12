use crate::{
    error::CryptoError,
    key_sources::{BytesKeySources, KeySources, VectorBytesKeySource},
};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_::{
        self,
        curve25519xsalsa20poly1305::{PublicKey, SecretKey},
    },
    secretbox::{self, xsalsa20poly1305::Key},
};
use std::convert::{TryFrom, TryInto};

pub trait SymmetricKeyEncryptor {
    fn try_encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, CryptoError>;
}

pub trait AsymmetricKeyEncryptor {
    fn try_encrypt(
        &self,
        public_ks: &KeySources,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Keys {
    Symmetric(SymmetricKeys),
    Asymmetric(AsymmetricKeys),
}

impl TryFrom<Keys> for SymmetricKeys {
    type Error = CryptoError;

    fn try_from(key: Keys) -> Result<Self, Self::Error> {
        match key {
            Keys::Symmetric(sk) => Ok(sk),
            _ => Err(CryptoError::NotSymmetric),
        }
    }
}

impl TryFrom<Keys> for AsymmetricKeys {
    type Error = CryptoError;

    fn try_from(key: Keys) -> Result<Self, Self::Error> {
        match key {
            Keys::Asymmetric(ak) => Ok(ak),
            _ => Err(CryptoError::NotAsymmetric),
        }
    }
}

impl TryFrom<Keys> for SecretKeys {
    type Error = CryptoError;

    fn try_from(key: Keys) -> Result<Self, Self::Error> {
        let asym_key: AsymmetricKeys = key.try_into()?;
        asym_key.try_into()
    }
}

impl TryFrom<Keys> for PublicKeys {
    type Error = CryptoError;

    fn try_from(key: Keys) -> Result<Self, Self::Error> {
        let asym_key: AsymmetricKeys = key.try_into()?;
        asym_key.try_into()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SymmetricKeys {
    SodiumOxide(SodiumOxideSymmetricKey),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKey {
    pub source: KeySources,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub name: String,
}

impl SymmetricKeyEncryptor for SodiumOxideSymmetricKey {
    fn try_encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let bks: BytesKeySources = (&self.source).try_into()?;
        let key_bytes = bks.get()?;
        let key = Key::from_slice(key_bytes).ok_or(CryptoError::SourceKeyBadSize)?;
        let nonce = secretbox::gen_nonce();
        Ok(secretbox::seal(&plaintext, &nonce, &key))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AsymmetricKeys {
    Public(PublicKeys),
    Secret(SecretKeys),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PublicKeys {
    SodiumOxide(SodiumOxidePublicKey),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecretKeys {
    SodiumOxide(SodiumOxideSecretKey),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicKey {
    pub source: KeySources,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub name: String,
}

impl TryFrom<AsymmetricKeys> for SecretKeys {
    type Error = CryptoError;

    fn try_from(ak: AsymmetricKeys) -> Result<Self, Self::Error> {
        match ak {
            AsymmetricKeys::Secret(sk) => Ok(sk),
            _ => Err(CryptoError::NotSecret),
        }
    }
}

impl TryFrom<AsymmetricKeys> for PublicKeys {
    type Error = CryptoError;

    fn try_from(ak: AsymmetricKeys) -> Result<Self, Self::Error> {
        match ak {
            AsymmetricKeys::Secret(sk) => sk.try_into(),
            AsymmetricKeys::Public(pk) => Ok(pk),
        }
    }
}

impl TryFrom<SecretKeys> for PublicKeys {
    type Error = CryptoError;

    fn try_from(sk: SecretKeys) -> Result<Self, Self::Error> {
        match sk {
            SecretKeys::SodiumOxide(sosk) => {
                let secret_key = SecretKey::from_slice(
                    TryInto::<BytesKeySources>::try_into(sosk.source)?.get()?,
                )
                .ok_or(CryptoError::SourceKeyBadSize)?;
                let public_key = secret_key.public_key();
                let vbks = VectorBytesKeySource::new(public_key.as_ref());

                Ok(PublicKeys::SodiumOxide(SodiumOxidePublicKey {
                    source: KeySources::Bytes(BytesKeySources::Vector(vbks)),
                    alg: "curve25519xsalsa20poly1305".to_owned(),
                    encrypted_by: None,
                    name: sosk.name,
                }))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretKey {
    pub source: KeySources,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub name: String,
}

impl AsymmetricKeyEncryptor for SecretKeys {
    fn try_encrypt(
        &self,
        public_ks: &KeySources,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        match self {
            SecretKeys::SodiumOxide(sosk) => sosk.try_encrypt(public_ks, plaintext),
        }
    }
}

impl TryFrom<SodiumOxideSecretKey> for SodiumOxidePublicKey {
    type Error = CryptoError;

    fn try_from(sosk: SodiumOxideSecretKey) -> Result<Self, Self::Error> {
        let bks: BytesKeySources = sosk.source.try_into()?;
        let secret_key_bytes = bks.get()?;

        let secret_key =
            SecretKey::from_slice(secret_key_bytes).ok_or(CryptoError::SourceKeyBadSize)?;
        let public_key = secret_key.public_key();
        Ok(SodiumOxidePublicKey {
            source: KeySources::Bytes(BytesKeySources::Vector(VectorBytesKeySource::new(
                public_key.as_ref(),
            ))),
            alg: "curve25519xsalsa20poly1305".to_owned(),
            encrypted_by: None,
            name: sosk.name,
        })
    }
}

impl AsymmetricKeyEncryptor for SodiumOxideSecretKey {
    fn try_encrypt(
        &self,
        public_ks: &KeySources,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let secret_bks: BytesKeySources = (&self.source).try_into()?;
        let public_bks: BytesKeySources = public_ks.try_into()?;
        let secret_key_bytes = secret_bks.get()?;
        let public_key_bytes = public_bks.get()?;
        let secret_key =
            SecretKey::from_slice(secret_key_bytes).ok_or(CryptoError::SourceKeyBadSize)?;
        let public_key =
            PublicKey::from_slice(public_key_bytes).ok_or(CryptoError::SourceKeyBadSize)?;
        let precomputed_key = box_::precompute(&public_key, &secret_key);
        let nonce = box_::gen_nonce();
        Ok(box_::seal_precomputed(&plaintext, &nonce, &precomputed_key))
    }
}
