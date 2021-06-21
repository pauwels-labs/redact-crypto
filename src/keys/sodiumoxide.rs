use crate::{
    Buildable, Builder, Builders, BytesSources, CryptoError, Name, States, Storer, Unsealer,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_::curve25519xsalsa20poly1305::{
        PublicKey as ExternalSodiumOxidePublicAsymmetricKey,
        SecretKey as ExternalSodiumOxideSecretAsymmetricKey,
        PUBLICKEYBYTES as EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES,
        SECRETKEYBYTES as EXTERNALSODIUMOXIDESECRETASYMMETRICKEYBYTES,
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
pub struct SodiumOxideSymmetricKeyUnsealable {
    pub source: BytesSources,
    pub key: Box<States>,
    pub nonce: ExternalSodiumOxideSymmetricNonce,
}

#[async_trait]
impl Unsealer for SodiumOxideSymmetricKeyUnsealable {
    async fn unseal<T: Storer>(&self, storer: T) -> Result<Vec<u8>, CryptoError> {
        let key = match *self.key {
            States::Referenced { ref name } => {
                storer
                    .get::<SodiumOxideSymmetricKey>(&name)
                    .await
                    .map_err(|e| CryptoError::StorageError { source: e })?
            }
            States::Sealed {
                ref builder,
                ref unsealable,
            } => {
                let bytes = unsealable.unseal(storer).await?;
                let builder = <SodiumOxideSymmetricKey as Buildable>::Builder::try_from(builder)?;
                builder.build(bytes.as_ref())?
            }
            States::Unsealed {
                ref builder,
                ref bytes,
            } => {
                let builder = <SodiumOxideSymmetricKey as Buildable>::Builder::try_from(builder)?;
                builder.build(bytes.as_ref())?
            }
        };

        let bytes = self.source.get()?;
        Ok(key.unseal(bytes.as_ref(), &self.nonce)?)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct SodiumOxideSymmetricKeyBuilder {}

impl TryFrom<Builders> for SodiumOxideSymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: Builders) -> Result<Self, Self::Error> {
        match builder {
            Builders::SodiumOxideSymmetricKey(soskb) => Ok(soskb),
        }
    }
}

impl TryFrom<&Builders> for SodiumOxideSymmetricKeyBuilder {
    type Error = CryptoError;

    fn try_from(builder: &Builders) -> Result<Self, Self::Error> {
        match builder {
            Builders::SodiumOxideSymmetricKey(soskb) => Ok(*soskb),
        }
    }
}

impl Builder for SodiumOxideSymmetricKeyBuilder {
    type Output = SodiumOxideSymmetricKey;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        Ok(SodiumOxideSymmetricKey {
            key: ExternalSodiumOxideSymmetricKey::from_slice(bytes).ok_or(
                CryptoError::InvalidKeyLength {
                    expected: SodiumOxideSymmetricKey::KEYBYTES,
                    actual: bytes.len(),
                },
            )?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKey {
    pub key: ExternalSodiumOxideSymmetricKey,
}

impl Buildable for SodiumOxideSymmetricKey {
    type Builder = SodiumOxideSymmetricKeyBuilder;

    fn builder() -> Self::Builder {
        SodiumOxideSymmetricKeyBuilder {}
    }
}

impl SodiumOxideSymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDESYMMETRICKEYBYTES;

    pub fn seal(&self, plaintext: &[u8], nonce: &ExternalSodiumOxideSymmetricNonce) -> Vec<u8> {
        secretbox::seal(plaintext, nonce, &self.key)
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

// impl Stateful for SodiumOxideSymmetricKey {
//     type ReferenceType = SodiumOxideSymmetricKeyReference;
//     type SealedType = Unsealables;
//     type UnsealedType = Self;
// }

// impl From<SodiumOxideSymmetricKey> for TypeReferences {
//     fn from(key: SodiumOxideSymmetricKey) -> Self {
//         let key_ref = SodiumOxideSymmetricKeyReference {
//             name: key.name.clone(),
//         };

//         TypeReferences::Keys(KeyTypeReferences::Symmetric(
//             SymmetricKeyTypeReferences::SodiumOxide(key_ref),
//         ))
//     }
// }

// impl TryFrom<Types> for SodiumOxideSymmetricKey {
//     type Error = CryptoError;

//     fn try_from(st: Types) -> Result<Self, Self::Error> {
//         let skt = SymmetricKeyTypes::try_from(st)?;
//         match skt {
//             SymmetricKeyTypes::SodiumOxide(sosk) => Ok(sosk),
//         }
//     }
// }

// impl TryFrom<BytesSources> for SodiumOxideSymmetricKey {
//     type Error = CryptoError;

//     fn try_from(source: BytesSources) -> Result<Self, Self::Error> {
//         let bytes = source.get()?;
//         Ok(SodiumOxideSymmetricKey {
//             name: source.name(),
//             key: ExternalSodiumOxideSymmetricKey::from_slice(bytes).ok_or(
//                 CryptoError::InvalidKeyLength {
//                     expected: SodiumOxideSymmetricKey::KEYBYTES,
//                     actual: bytes.len(),
//                 },
//             )?,
//         })
//     }
// }

// impl TryFrom<Sources> for SodiumOxideSymmetricKey {
//     type Error = CryptoError;

//     fn try_from(source: Sources) -> Result<Self, Self::Error> {
//         match source {
//             Sources::Bytes(bs) => bs.try_into(),
//         }
//     }
// }

// SECRET ASYMMETRIC KEY \\

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKeyReference {
    pub name: Name,
}

// impl Stateful for SodiumOxideSecretAsymmetricKeyReference {
//     type ReferenceType = Self;
//     type SealedType = Unsealables;
//     type UnsealedType = SodiumOxideSecretAsymmetricKey;
// }

// #[async_trait]
// impl Dereferencable for SodiumOxideSecretAsymmetricKeyReference {
//     async fn dereference<'a, T: TryFrom<&'a [u8], Error = CryptoError> + Stateful, S: Storer>(
//         &self,
//         store: S,
//     ) -> Result<TypeStates<T>, StorageError> {
//         store.get(&self.name).await
//     }
// }

// impl TryFrom<TypeReferences> for SodiumOxideSecretAsymmetricKeyReference {
//     type Error = CryptoError;

//     fn try_from(tr: TypeReferences) -> Result<Self, Self::Error> {
//         let saktr = SecretAsymmetricKeyTypeReferences::try_from(tr)?;
//         match saktr {
//             SecretAsymmetricKeyTypeReferences::SodiumOxide(sosakr) => Ok(sosakr),
//         }
//     }
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct SealedSodiumOxideSecretAsymmetricKey {
//     pub source: BytesSources,
//     pub unsealedby: KeyTypeReferences,
// }

// impl Stateful for SealedSodiumOxideSecretAsymmetricKey {
//     type ReferenceType = SodiumOxideSecretAsymmetricKeyReference;
//     type SealedType = Self;
//     type UnsealedType = SodiumOxideSecretAsymmetricKey;
// }

// // impl Unsealable for SealedSodiumOxideSecretAsymmetricKey {
// //     type UnsealedType = SodiumOxideSecretAsymmetricKey;

// //     fn try_unseal(&self, unsealer: Box<dyn Unsealer>) -> Result<Self::UnsealedType, CryptoError> {
// //         let unsealed_bytes = unsealer.try_unseal(&self.source)?;
// //         let key = ExternalSodiumOxideSecretAsymmetricKey::from_slice(unsealed_bytes.get()?)
// //             .ok_or(CryptoError::SourceKeyBadSize)?;
// //         Ok(SodiumOxideSecretAsymmetricKey { key })
// //     }
// // }

// impl TryFrom<SealedTypes> for SealedSodiumOxideSecretAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(st: SealedTypes) -> Result<Self, Self::Error> {
//         let ssakt = SealedSecretAsymmetricKeyTypes::try_from(st)?;
//         match ssakt {
//             SealedSecretAsymmetricKeyTypes::SodiumOxide(ssosak) => Ok(ssosak),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKey {
    pub key: ExternalSodiumOxideSecretAsymmetricKey,
}

impl SodiumOxideSecretAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDESECRETASYMMETRICKEYBYTES;
}

// impl Stateful for SodiumOxideSecretAsymmetricKey {
//     type ReferenceType = SodiumOxideSecretAsymmetricKeyReference;
//     type SealedType = Unsealables;
//     type UnsealedType = Self;
// }

// impl Sealable for SodiumOxideSecretAsymmetricKey {
//     type SealedType = SealedSodiumOxideSecretAsymmetricKey;

//     fn try_seal(&self, sealer: Box<dyn Sealer>) -> Result<Self::SealedType, CryptoError> {
//         let key_bytes = self.key.as_ref();
//         let vbs = VectorBytesSource::new(Some(key_bytes));
//         let bs = BytesSources::Vector(vbs);
//         let sealed_bs = sealer.try_seal(bs)?;
//         Ok(SealedSodiumOxideSecretAsymmetricKey {
//             source: sealed_bs,
//             unsealedby: sealer.get_ref(),
//         })
//     }
// }

// impl TryFrom<Types> for SodiumOxideSecretAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(st: Types) -> Result<Self, Self::Error> {
//         let sakt = SecretAsymmetricKeyTypes::try_from(st)?;
//         match sakt {
//             SecretAsymmetricKeyTypes::SodiumOxide(sosak) => Ok(sosak),
//         }
//     }
// }

// impl TryFrom<BytesSources> for SodiumOxideSecretAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(source: BytesSources) -> Result<Self, Self::Error> {
//         let bytes = source.get()?;
//         Ok(SodiumOxideSecretAsymmetricKey {
//             key: ExternalSodiumOxideSecretAsymmetricKey::from_slice(bytes).ok_or(
//                 CryptoError::InvalidKeyLength {
//                     expected: SodiumOxideSecretAsymmetricKey::KEYBYTES,
//                     actual: bytes.len(),
//                 },
//             )?,
//         })
//     }
// }

// impl TryFrom<Sources> for SodiumOxideSecretAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(source: Sources) -> Result<Self, Self::Error> {
//         match source {
//             Sources::Bytes(bs) => bs.try_into(),
//         }
//     }
// }

// PUBLIC ASYMMETRIC KEY \\

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicAsymmetricKeyReference {
    pub name: Name,
}

// impl Stateful for SodiumOxidePublicAsymmetricKeyReference {
//     type ReferenceType = Self;
//     type SealedType = Unsealables;
//     type UnsealedType = SodiumOxidePublicAsymmetricKey;
// }

// #[async_trait]
// impl Dereferencable for SodiumOxidePublicAsymmetricKeyReference {
//     async fn dereference<'a, T: TryFrom<&'a [u8], Error = CryptoError> + Stateful, S: Storer>(
//         &self,
//         store: S,
//     ) -> Result<TypeStates<T>, StorageError> {
//         store.get(&self.name).await
//     }
// }

// impl TryFrom<TypeReferences> for SodiumOxidePublicAsymmetricKeyReference {
//     type Error = CryptoError;

//     fn try_from(tr: TypeReferences) -> Result<Self, Self::Error> {
//         let saktr = PublicAsymmetricKeyTypeReferences::try_from(tr)?;
//         match saktr {
//             PublicAsymmetricKeyTypeReferences::SodiumOxide(sosakr) => Ok(sosakr),
//         }
//     }
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct SealedSodiumOxidePublicAsymmetricKey {
//     pub source: BytesSources,
//     pub unsealedby: KeyTypeReferences,
// }

// impl Stateful for SealedSodiumOxidePublicAsymmetricKey {
//     type ReferenceType = SodiumOxidePublicAsymmetricKeyReference;
//     type SealedType = Self;
//     type UnsealedType = SodiumOxidePublicAsymmetricKey;
// }

// // impl Unsealable for SealedSodiumOxidePublicAsymmetricKey {
// //     type UnsealedType = SodiumOxidePublicAsymmetricKey;

// //     fn try_unseal(&self, unsealer: Box<dyn Unsealer>) -> Result<Self::UnsealedType, CryptoError> {
// //         let unsealed_bytes = unsealer.try_unseal(&self.source)?;
// //         let key = ExternalSodiumOxidePublicAsymmetricKey::from_slice(unsealed_bytes.get()?)
// //             .ok_or(CryptoError::SourceKeyBadSize)?;
// //         Ok(SodiumOxidePublicAsymmetricKey { key })
// //     }
// // }

// impl TryFrom<SealedTypes> for SealedSodiumOxidePublicAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(st: SealedTypes) -> Result<Self, Self::Error> {
//         let ssakt = SealedPublicAsymmetricKeyTypes::try_from(st)?;
//         match ssakt {
//             SealedPublicAsymmetricKeyTypes::SodiumOxide(ssosak) => Ok(ssosak),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicAsymmetricKey {
    pub key: ExternalSodiumOxidePublicAsymmetricKey,
}

impl SodiumOxidePublicAsymmetricKey {
    pub const KEYBYTES: usize = EXTERNALSODIUMOXIDEPUBLICASYMMETRICKEYBYTES;
}

// impl Stateful for SodiumOxidePublicAsymmetricKey {
//     type ReferenceType = SodiumOxidePublicAsymmetricKeyReference;
//     type SealedType = Unsealables;
//     type UnsealedType = Self;
// }

// impl Sealable for SodiumOxidePublicAsymmetricKey {
//     type SealedType = SealedSodiumOxidePublicAsymmetricKey;

//     fn try_seal(&self, sealer: Box<dyn Sealer>) -> Result<Self::SealedType, CryptoError> {
//         let key_bytes = self.key.as_ref();
//         let vbs = VectorBytesSource::new(Some(key_bytes));
//         let bs = BytesSources::Vector(vbs);
//         let sealed_bs = sealer.try_seal(bs)?;
//         Ok(SealedSodiumOxidePublicAsymmetricKey {
//             source: sealed_bs,
//             unsealedby: sealer.get_ref(),
//         })
//     }
// }

// impl TryFrom<Types> for SodiumOxidePublicAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(st: Types) -> Result<Self, Self::Error> {
//         let sakt = PublicAsymmetricKeyTypes::try_from(st)?;
//         match sakt {
//             PublicAsymmetricKeyTypes::SodiumOxide(sosak) => Ok(sosak),
//         }
//     }
// }

// impl TryFrom<BytesSources> for SodiumOxidePublicAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(source: BytesSources) -> Result<Self, Self::Error> {
//         let bytes = source.get()?;
//         Ok(SodiumOxidePublicAsymmetricKey {
//             key: ExternalSodiumOxidePublicAsymmetricKey::from_slice(bytes).ok_or(
//                 CryptoError::InvalidKeyLength {
//                     expected: SodiumOxidePublicAsymmetricKey::KEYBYTES,
//                     actual: bytes.len(),
//                 },
//             )?,
//         })
//     }
// }

// impl TryFrom<Sources> for SodiumOxidePublicAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(source: Sources) -> Result<Self, Self::Error> {
//         match source {
//             Sources::Bytes(bs) => bs.try_into(),
//         }
//     }
// }
