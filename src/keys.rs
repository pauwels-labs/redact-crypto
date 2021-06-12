pub mod sodiumoxide;

use crate::keys::sodiumoxide::{
    SodiumOxidePublicAsymmetricKey, SodiumOxideSecretAsymmetricKey, SodiumOxideSymmetricKey,
};
use serde::{Deserialize, Serialize};

pub type KeyName = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "key_type")]
pub enum Keys {
    Symmetric(SymmetricKeys),
    Asymmetric(AsymmetricKeys),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "executor")]
pub enum SymmetricKeys {
    SodiumOxide(SodiumOxideSymmetricKey),
}

// impl<T: Sealer> Sealable<T> for SymmetricKeys {
//     type SealedType = Self;

//     fn try_seal(&self, sealer: T) -> Result<Self::SealedType, CryptoError> {
//         match self {
//             Self::SodiumOxide(sk) => Ok(SymmetricKeys::SodiumOxide(sk.try_seal(sealer))),
//         }
//     }
// /// Encrypts the given plaintext using this symmetric key.
// pub fn try_seal<T: Sealable>(
//     &self,
//     plaintext: T,
//     nonce: Option<&SymmetricNonces>,
// ) -> Result<T::SealedType, CryptoError> {
//     plaintext.try_seal()
//     match self {
//         SymmetricKeys::SodiumOxide(sosk) => {
//             let plaintext = match plaintext {
//                 Sources::Bytes(bs) => bs,
//             };
//             let nonce = match nonce {
//                 Some(nonce) => Some(match nonce {
//                     SymmetricNonces::SodiumOxide(sn) => sn,
//                 }),
//                 None => None,
//             };

//             sosk.try_seal(plaintext, nonce)
//         }
//     }
// }

// /// Decrypts the given plaintext using this symmetric key and the nonce used during
// /// encryption.
// pub fn try_unseal(
//     &self,
//     sealed_source: &Sources,
//     nonce: &SymmetricNonces,
// ) -> Result<Sources, CryptoError> {
//     match self {
//         SymmetricKeys::SodiumOxide(sosk) => {
//             let sealed_source = match sealed_source {
//                 Sources::Bytes(bs) => bs,
//             };
//             let nonce = match nonce {
//                 SymmetricNonces::SodiumOxide(sosn) => sosn,
//             };
//             Ok(Sources::Bytes(BytesSources::Vector(
//                 sosk.try_unseal(sealed_source, nonce)?,
//             )))
//         }
//     }
// }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "asymmetric_key_type")]
pub enum AsymmetricKeys {
    Secret(SecretAsymmetricKeys),
    Public(PublicAsymmetricKeys),
}

// impl AsymmetricKeys {
//     /// Encrypts the given plaintext using this symmetric key.
//     pub fn try_seal(
//         &self,
//         akey: &AsymmetricKeys,
//         plaintext: &Sources,
//         nonce: Option<&AsymmetricNonces>,
//     ) -> Result<SealedSource, CryptoError> {
//         match self {
//             Self::Public(pak) => {
//                 let sak = match akey {
//                     AsymmetricKeys::Secret(sak) => Ok(sak),
//                     AsymmetricKeys::Public(_) => Err(CryptoError::ExpectedSecretKey),
//                 }?;

//                 pak.try_seal(sak, plaintext, nonce)
//             }
//             Self::Secret(sak) => {
//                 let pak = match akey {
//                     AsymmetricKeys::Public(pak) => Ok(pak),
//                     AsymmetricKeys::Secret(_) => Err(CryptoError::ExpectedPublicKey),
//                 }?;

//                 sak.try_seal(pak, plaintext, nonce)
//             }
//         }
//     }

//     /// Decrypts the given plaintext using this symmetric key and the nonce used during
//     /// encryption.
//     pub fn try_unseal(
//         &self,
//         akey: &AsymmetricKeys,
//         sealed_source: &Sources,
//         nonce: &AsymmetricNonces,
//     ) -> Result<Sources, CryptoError> {
//         match self {
//             Self::Public(pak) => {
//                 let sak = match akey {
//                     AsymmetricKeys::Secret(sak) => Ok(sak),
//                     AsymmetricKeys::Public(_) => Err(CryptoError::ExpectedSecretKey),
//                 }?;
//                 pak.try_unseal(sak, sealed_source, nonce)
//             }
//             Self::Secret(sak) => {
//                 let pak = match akey {
//                     AsymmetricKeys::Public(pak) => Ok(pak),
//                     AsymmetricKeys::Secret(_) => Err(CryptoError::ExpectedPublicKey),
//                 }?;
//                 sak.try_unseal(pak, sealed_source, nonce)
//             }
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "executor")]
pub enum SecretAsymmetricKeys {
    SodiumOxide(SodiumOxideSecretAsymmetricKey),
}

// impl SecretAsymmetricKeys {
//     /// Encrypts the given plaintext using this symmetric key.
//     pub fn try_seal(
//         &self,
//         public_key: &PublicAsymmetricKeys,
//         plaintext: &Sources,
//         nonce: Option<&AsymmetricNonces>,
//     ) -> Result<SealedSource, CryptoError> {
//         match self {
//             Self::SodiumOxide(sak) => {
//                 let public_key = match public_key {
//                     PublicAsymmetricKeys::SodiumOxide(sopak) => sopak,
//                 };
//                 let plaintext = match plaintext {
//                     Sources::Bytes(bs) => bs,
//                 };
//                 let nonce = match nonce {
//                     Some(nonce) => Some(match nonce {
//                         AsymmetricNonces::SodiumOxide(an) => an,
//                     }),
//                     None => None,
//                 };

//                 sak.try_seal(public_key, plaintext, nonce)
//             }
//         }
//     }

//     /// Decrypts the given plaintext using this symmetric key and the nonce used during
//     /// encryption.
//     pub fn try_unseal(
//         &self,
//         public_key: &PublicAsymmetricKeys,
//         sealed_source: &Sources,
//         nonce: &AsymmetricNonces,
//     ) -> Result<Sources, CryptoError> {
//         match self {
//             Self::SodiumOxide(sak) => {
//                 let public_key = match public_key {
//                     PublicAsymmetricKeys::SodiumOxide(sopak) => sopak,
//                 };
//                 let sealed_source = match sealed_source {
//                     Sources::Bytes(bs) => bs,
//                 };
//                 let nonce = match nonce {
//                     AsymmetricNonces::SodiumOxide(an) => an,
//                 };

//                 Ok(Sources::Bytes(BytesSources::Vector(sak.try_unseal(
//                     public_key,
//                     sealed_source,
//                     nonce,
//                 )?)))
//             }
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "executor")]
pub enum PublicAsymmetricKeys {
    SodiumOxide(SodiumOxidePublicAsymmetricKey),
}

// impl PublicAsymmetricKeys {
//     /// Encrypts the given plaintext using this symmetric key.
//     pub fn try_seal(
//         &self,
//         secret_key: &SecretAsymmetricKeys,
//         plaintext: &Sources,
//         nonce: Option<&AsymmetricNonces>,
//     ) -> Result<SealedSource, CryptoError> {
//         match self {
//             Self::SodiumOxide(pak) => {
//                 let secret_key = match secret_key {
//                     SecretAsymmetricKeys::SodiumOxide(sopak) => sopak,
//                 };
//                 let plaintext = match plaintext {
//                     Sources::Bytes(bs) => bs,
//                 };
//                 let nonce = match nonce {
//                     Some(nonce) => Some(match nonce {
//                         AsymmetricNonces::SodiumOxide(an) => an,
//                     }),
//                     None => None,
//                 };

//                 pak.try_seal(secret_key, plaintext, nonce)
//             }
//         }
//     }

//     /// Decrypts the given plaintext using this symmetric key and the nonce used during
//     /// encryption.
//     pub fn try_unseal(
//         &self,
//         secret_key: &SecretAsymmetricKeys,
//         sealed_source: &Sources,
//         nonce: &AsymmetricNonces,
//     ) -> Result<Sources, CryptoError> {
//         match self {
//             Self::SodiumOxide(pak) => {
//                 let secret_key = match secret_key {
//                     SecretAsymmetricKeys::SodiumOxide(sopak) => sopak,
//                 };
//                 let sealed_source = match sealed_source {
//                     Sources::Bytes(bs) => bs,
//                 };
//                 let nonce = match nonce {
//                     AsymmetricNonces::SodiumOxide(an) => an,
//                 };

//                 Ok(Sources::Bytes(BytesSources::Vector(pak.try_unseal(
//                     secret_key,
//                     sealed_source,
//                     nonce,
//                 )?)))
//             }
//         }
//     }
// }
