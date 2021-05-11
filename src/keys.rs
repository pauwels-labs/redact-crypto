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
    fn try_encrypt(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, CryptoError>;
}

pub trait AsymmetricKeyEncryptor {
    fn try_encrypt(
        &mut self,
        public_ks: &mut KeySources,
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

impl SymmetricKeys {
    pub fn refresh(&mut self) -> Result<(), CryptoError> {
        match self {
            SymmetricKeys::SodiumOxide(sosk) => sosk.refresh(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKey {
    pub source: KeySources,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub name: String,
}

impl SodiumOxideSymmetricKey {
    pub fn refresh(&mut self) -> Result<(), CryptoError> {
        let bks: &mut BytesKeySources = match self.source {
            KeySources::Bytes(ref mut bks) => Ok(bks),
        }?;

        let key = secretbox::gen_key();
        bks.set(key.as_ref())?;
        Ok(())
    }
}

impl SymmetricKeyEncryptor for SodiumOxideSymmetricKey {
    fn try_encrypt(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let bks: &mut BytesKeySources = match self.source {
            KeySources::Bytes(ref mut bks) => Ok(bks),
        }?;
        let key_bytes_result = bks.get();
        let key_bytes = match key_bytes_result {
            Ok(bytes) => Ok(bytes),
            Err(e) => match e {
                CryptoError::NotFound => {
                    let key = secretbox::gen_key();
                    bks.set(key.as_ref())?;
                    bks.get()
                }
                _ => Err(e),
            },
        }?;
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

impl SecretKeys {
    pub fn refresh(&mut self) -> Result<(), CryptoError> {
        match self {
            SecretKeys::SodiumOxide(sosk) => sosk.refresh(),
        }
    }
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
                let vbks = VectorBytesKeySource {
                    value: Some(public_key.as_ref().to_vec()),
                };

                Ok(PublicKeys::SodiumOxide(SodiumOxidePublicKey {
                    source: KeySources::Bytes(BytesKeySources::Vector(vbks)),
                    alg: "".to_owned(),
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
        &mut self,
        public_ks: &mut KeySources,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        match self {
            SecretKeys::SodiumOxide(sosk) => sosk.try_encrypt(public_ks, plaintext),
        }
    }
}

impl SodiumOxideSecretKey {
    pub fn public_key(&mut self) -> Result<SodiumOxidePublicKey, CryptoError> {
        let bks: &mut BytesKeySources = match self.source {
            KeySources::Bytes(ref mut bks) => Ok(bks),
        }?;
        let secret_key_bytes_result = bks.get();
        let secret_key_bytes = match secret_key_bytes_result {
            Ok(bytes) => Ok(bytes),
            Err(e) => match e {
                CryptoError::NotFound => {
                    self.refresh()?;
                    let bytes = match self.source {
                        KeySources::Bytes(ref mut bks) => bks.get(),
                    }?;
                    Ok(bytes)
                }
                _ => Err(e),
            },
        }?;

        let secret_key =
            SecretKey::from_slice(secret_key_bytes).ok_or(CryptoError::SourceKeyBadSize)?;
        let public_key = secret_key.public_key();
        Ok(SodiumOxidePublicKey {
            source: KeySources::Bytes(BytesKeySources::Vector(VectorBytesKeySource {
                value: Some(public_key.as_ref().to_vec()),
            })),
            alg: "curve25519xsalsa20poly1305".to_owned(),
            encrypted_by: None,
            name: self.name.clone(),
        })
    }

    pub fn refresh(&mut self) -> Result<(), CryptoError> {
        let bks: &mut BytesKeySources = match self.source {
            KeySources::Bytes(ref mut bks) => Ok(bks),
        }?;

        let (_, sk) = box_::gen_keypair();
        bks.set(sk.as_ref())?;
        Ok(())
    }
}

impl AsymmetricKeyEncryptor for SodiumOxideSecretKey {
    fn try_encrypt(
        &mut self,
        public_ks: &mut KeySources,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let secret_bks: &mut BytesKeySources = match self.source {
            KeySources::Bytes(ref mut bks) => Ok(bks),
        }?;
        let public_bks: &mut BytesKeySources = match public_ks {
            KeySources::Bytes(ref mut bks) => Ok(bks),
        }?;
        let secret_key_bytes_result = secret_bks.get();
        let secret_key_bytes = match secret_key_bytes_result {
            Ok(bytes) => Ok(bytes),
            Err(e) => match e {
                CryptoError::NotFound => {
                    let (_, sk) = box_::gen_keypair();
                    secret_bks.set(sk.as_ref())?;
                    secret_bks.get()
                }
                _ => Err(e),
            },
        }?;
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
