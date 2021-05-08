use crate::{
    error::CryptoError,
    key_sources::{KeySources, ValueKeySource},
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
        public_ks: KeySources,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError>;
}

pub enum Keys {
    Symmetric(SymmetricKeys),
    Asymmetric(AsymmetricKeys),
}

pub enum SymmetricKeys {
    SodiumOxide(SodiumOxideSymmetricKey),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideSymmetricKey {
    pub source: KeySources,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub name: String,
}

impl SymmetricKeyEncryptor for SodiumOxideSymmetricKey {
    fn try_encrypt(&self, plaintext: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let vks: ValueKeySource = self.source.clone().try_into()?;
        let key = Key::from_slice(vks.bytes()).ok_or(CryptoError::SourceKeyBadSize)?;
        let nonce = secretbox::gen_nonce();
        Ok(secretbox::seal(&plaintext, &nonce, &key))
    }
}

pub enum AsymmetricKeys {
    Public(PublicKeys),
    Secret(SecretKeys),
}

pub enum PublicKeys {
    SodiumOxide(SodiumOxidePublicKey),
}

pub enum SecretKeys {
    SodiumOxide(SodiumOxideSecretKey),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxidePublicKey {
    pub source: KeySources,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub name: String,
}

impl TryFrom<SecretKeys> for PublicKeys {
    type Error = CryptoError;

    fn try_from(sk: SecretKeys) -> Result<Self, Self::Error> {
        match sk {
            SecretKeys::SodiumOxide(sosk) => {
                let public_vks: ValueKeySource = sosk.source.try_into()?;
                Ok(PublicKeys::SodiumOxide(SodiumOxidePublicKey {
                    source: KeySources::Value(public_vks),
                    alg: "".to_owned(),
                    encrypted_by: None,
                    name: sosk.name,
                }))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SodiumOxideSecretKey {
    pub source: KeySources,
    pub alg: String,
    pub encrypted_by: Option<String>,
    pub name: String,
}

impl AsymmetricKeyEncryptor for SodiumOxideSecretKey {
    fn try_encrypt(
        &self,
        public_ks: KeySources,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let secret_vks: ValueKeySource = self.source.clone().try_into()?;
        let public_vks: ValueKeySource = public_ks.try_into()?;
        let secret_key =
            SecretKey::from_slice(secret_vks.bytes()).ok_or(CryptoError::SourceKeyBadSize)?;
        let public_key =
            PublicKey::from_slice(public_vks.bytes()).ok_or(CryptoError::SourceKeyBadSize)?;
        let precomputed_key = box_::precompute(&public_key, &secret_key);
        let nonce = box_::gen_nonce();
        Ok(box_::seal_precomputed(&plaintext, &nonce, &precomputed_key))
    }
}
