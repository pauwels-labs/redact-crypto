use crate::{
    nonces::sodiumoxide::AsymmetricNonce, BytesSources, CryptoError, KeyName, KeyTypeReferences,
    VectorBytesSource,
};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_::{
        self,
        curve25519xsalsa20poly1305::{
            PublicKey as ExternalPublicKey, SecretKey as ExternalSecretKey,
        },
    },
    secretbox::xsalsa20poly1305::Key as ExternalSymmetricKey,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKeyReference {
    pub name: KeyName,
}

// impl TryFrom<Types> for SodiumOxideSymmetricKeyReference {
//     type Error = CryptoError;

//     fn try_from(value: Types) -> Result<Self, Self::Error> {
//         match value {
//             Types::Keys(KeyTypes::Symmetric(SymmetricKeyTypes::SodiumOxide(
//                 SodiumOxideSymmetricKeys::Reference(soskr),
//             ))) => Ok(soskr),
//             _ => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedSodiumOxideSymmetricKey {
    pub source: BytesSources,
    pub unsealedby: KeyTypeReferences,
}

// fn serialize_unsealedby<S>(
//     key: &Box<
//         dyn Fetchable<FetchedType = Box<dyn Unsealer<Input = BytesSources, Output = BytesSources>>>,
//     >,
//     serializer: S,
// ) -> Result<S::Ok, S::Error>
// where
//     S: Serializer,
// {
//     match key.get_type() {
//         Types::Keys(kt) => match kt {
//             KeyTypes::Symmetric(skt) => {
//                 serializer.serialize_newtype_variant("KeyTypes", 0, "Symmetric", &skt)
//             }
//             KeyTypes::Asymmetric(akt) => {
//                 serializer.serialize_newtype_variant("KeyTypes", 1, "Asymmetric", &akt)
//             }
//         },
//         Types::Data(dt) => Err(S::Error::custom),
//     }
// match key.get_type() {
//     TypeStates::Sealed(sts) => {
//         let concrete_type = sts.get_type();
//         match concrete_type {
//             Types::Keys(kt) => match kt {
//                 KeyTypes::Symmetric(skt) => {
//                     serializer.serialize_newtype_variant("KeyTypes", 0, "Symmetric", skt)
//                 }
//                 KeyTypes::Asymmetric(akt) => {
//                     serializer.serialize_newtype_variant("KeyTypes", 1, "Asymmetric", akt)
//                 }
//             },
//             Types::Data(dt) => Err(S::Error::custom),
//         }
//     }
//     TypeStates::Unsealed(uts) => match uts.get_key() {
//         KeyTypes::Symmetric(skt) => {
//             serializer.serialize_newtype_variant("KeyTypes", 0, "Symmetric", skt)
//         }
//         KeyTypes::Asymmetric(akt) => {
//             serializer.serialize_newtype_variant("KeyTypes", 1, "Asymmetric", akt)
//         }
//     },
//     TypeStates::Reference(rts) => {}
// TypeStates::Symmetric(ref s) => {
//     serializer.serialize_newtype_variant("KeyTypes", 0, "Symmetric", s)
// }
// KeyTypes::Asymmetric(ref a) => {
//     serializer.serialize_newtype_variant("KeyTypes", 1, "Asymmetric", a)
// }
// }
// }

// fn deserialize_unsealedby<'de, D>(
//     deserializer: D,
// ) -> Result<
//     Box<
//         dyn Fetchable<FetchedType = Box<dyn Unsealer<Input = BytesSources, Output = BytesSources>>>,
//     >,
//     D::Error,
// >
// where
//     D: Deserializer<'de>,
// {
//     let s: &str = de::Deserialize::deserialize(deserializer)?;
//     let key: KeyTypes = serde_json::from_str(s).map_err(de::Error::custom)?;
//     Ok(Box::new(key))
// }

// struct UnsealerStruct<T: Unsealer>(T);

// impl TryFrom<Types> for SealedSodiumOxideSymmetricKey {
//     type Error = CryptoError;

//     fn try_from(value: Types) -> Result<Self, Self::Error> {
//         match value {
//             Types::Keys(KeyTypes::Symmetric(SymmetricKeyTypes::SodiumOxide(
//                 SodiumOxideSymmetricKeys::Sealed(ssk),
//             ))) => Ok(ssk),
//             _ => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKey {
    pub key: ExternalSymmetricKey,
}

// impl TryFrom<Types> for SodiumOxideSymmetricKey {
//     type Error = CryptoError;

//     fn try_from(value: Types) -> Result<Self, Self::Error> {
//         match value {
//             Types::Keys(KeyTypes::Symmetric(SymmetricKeyTypes::SodiumOxide(
//                 SodiumOxideSymmetricKeys::Unsealed(sk),
//             ))) => Ok(sk),
//             _ => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

// impl TryFrom<BytesSources> for SymmetricKey {
//     type Error = CryptoError;

//     fn try_from(source: BytesSources) -> Result<Self, Self::Error> {
//         let bytes = source.get()?;
//         Ok(SymmetricKey {
//             key: ExternalSymmetricKey::from_slice(bytes).ok_or(CryptoError::InvalidKeyLength {
//                 expected: SymmetricKey::KEYBYTES,
//                 actual: bytes.len(),
//             })?,
//         })
//     }
// }

// impl TryFrom<Sources> for SymmetricKey {
//     type Error = CryptoError;

//     fn try_from(source: Sources) -> Result<Self, Self::Error> {
//         match source {
//             Sources::Bytes(bs) => bs.try_into(),
//         }
//     }
// }

// impl Sealable for SodiumOxideSymmetricKey {
//     type SealedType = SealedSodiumOxideSymmetricKey;

//     fn try_seal(
//         &self,
//         sealer: Box<
//             dyn Sealer<
//                 Input = <Self::SealedType as Unsealable>::UnsealedType,
//                 Output = Self::SealedType,
//             >,
//         >,
//     ) -> Result<Self::SealedType, CryptoError> {
//         let key_bytes = self.key.as_ref();
//         let vbs = VectorBytesSource {
//             value: Some(key_bytes.to_vec()),
//         };
//         let bs = BytesSources::Vector(vbs);
//         let sealed_bs = sealer.try_seal(bs)?;
//         Ok(SealedSodiumOxideSymmetricKey {
//             source: sealed_bs,
//             unsealedby: Box::new(sealer.into()),
//         })
//     }
// }

// impl Unsealable for SealedSodiumOxideSymmetricKey {
//     type UnsealedType = SodiumOxideSymmetricKey;

//     fn try_unseal(
//         &self,
//         unsealer: Box<
//             dyn Unsealer<
//                 Input = <Self::UnsealedType as Sealable>::SealedType,
//                 Output = Self::UnsealedType,
//             >,
//         >,
//     ) -> Result<Self::UnsealedType, CryptoError> {
//         let unsealed_bytes = unsealer.try_unseal(self.source)?.get()?;
//         let key = ExternalSymmetricKey::from_slice(unsealed_bytes)
//             .ok_or(CryptoError::SourceKeyBadSize)?;
//         Ok(SodiumOxideSymmetricKey { key })
//     }

//     fn get_type(&self) -> Types {
//         Types::Keys(KeyTypes::Symmetric(SymmetricKeyTypes::SodiumOxide(
//             SodiumOxideSymmetricKeys::Sealed(self),
//         )))
//     }
// }

// impl SymmetricKey {
//     pub const KEYBYTES: usize = EXTERNALSYMMETRICKEYBYTES;

//     /// Encrypts the given plaintext using this symmetric key.
//     pub fn try_seal(
//         &self,
//         bytes: &BytesSources,
//         nonce: Option<&SymmetricNonce>,
//     ) -> Result<VectorBytesSource, CryptoError> {
//         let nonce = match nonce {
//             Some(nonce) => nonce,
//             None => &SymmetricNonce {
//                 nonce: secretbox::gen_nonce(),
//             },
//         };
//         Ok(VectorBytesSource {
//             value: Some(secretbox::seal(&bytes.get()?, &nonce.nonce, &self.key)),
//         })
//         // Ok(SealedType {
//         //     source: Sources::Bytes(BytesSources::Vector(vbs)),
//         //     unsealedby: UnsealKeyRefs::Symmetric(SymmetricUnsealKeyRefs::SodiumOxide(
//         //         SymmetricDecryptionKeyRef {
//         //             name: self.name().to_owned(),
//         //             nonce: Nonces::Symmetric(SymmetricNonces::SodiumOxide(nonce.to_owned())),
//         //         },
//         //     )),
//         // })
//     }

//     /// Decrypts the given plaintext using this symmetric key and the nonce used during
//     /// encryption.
//     pub fn try_unseal(
//         &self,
//         sealed_source: &BytesSources,
//         nonce: &SymmetricNonce,
//     ) -> Result<VectorBytesSource, CryptoError> {
//         let ciphertext = sealed_source.get()?;
//         Ok(VectorBytesSource {
//             value: Some(
//                 secretbox::open(ciphertext, &nonce.nonce, &self.key)
//                     .map_err(|_| CryptoError::CiphertextFailedVerification)?
//                     .to_vec(),
//             ),
//         })
//     }
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub enum SodiumOxideSecretAsymmetricKeys {
//     Sealed(SealedSodiumOxideSecretAsymmetricKey),
//     Unsealed(SodiumOxideSecretAsymmetricKey),
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedSodiumOxideSecretAsymmetricKey {
    pub source: BytesSources,
    pub unsealedby: KeyTypeReferences,
}

// impl TryFrom<Types> for SealedSodiumOxideSecretAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(value: Types) -> Result<Self, Self::Error> {
//         match value {
//             Types::Keys(KeyTypes::Asymmetric(AsymmetricKeyTypes::Secret(
//                 SecretAsymmetricKeyTypes::SodiumOxide(SodiumOxideSecretAsymmetricKeys::Sealed(
//                     ssosak,
//                 )),
//             ))) => Ok(ssosak),
//             _ => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKey {
    pub key: ExternalSecretKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretAsymmetricKeyReference {
    pub name: KeyName,
}

// impl TryFrom<Types> for SodiumOxideSecretAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(value: Types) -> Result<Self, Self::Error> {
//         match value {
//             Types::Keys(KeyTypes::Asymmetric(AsymmetricKeyTypes::Secret(
//                 SecretAsymmetricKeyTypes::SodiumOxide(SodiumOxideSecretAsymmetricKeys::Unsealed(
//                     usosak,
//                 )),
//             ))) => Ok(usosak),
//             _ => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

impl SodiumOxideSecretAsymmetricKey {
    /// Encrypts the given plaintext using a given public key and this secret key. The given
    /// public key is permitted to be the public key associated with this secret key.
    pub fn try_seal(
        &self,
        public_key: &SodiumOxidePublicAsymmetricKey,
        plaintext: &BytesSources,
        nonce: Option<&AsymmetricNonce>,
    ) -> Result<VectorBytesSource, CryptoError> {
        let precomputed_key = box_::precompute(&public_key.key, &self.key);
        let nonce = match nonce {
            Some(nonce) => nonce.clone(),
            None => AsymmetricNonce {
                nonce: box_::gen_nonce(),
            },
        };
        Ok(VectorBytesSource::new(Some(
            box_::seal_precomputed(&plaintext.get()?, &nonce.nonce, &precomputed_key).as_ref(),
        )))
        // Ok(SealedSource {
        //     source: Sources::Bytes(BytesSources::Vector(vbs)),
        //     decryptedby: UnsealKeyRefs::Asymmetric(AsymmetricDecryptionKeyRefs::SodiumOxide(
        //         AsymmetricDecryptionKeyRef {
        //             name: self.name().to_owned(),
        //             nonce: Nonces::Asymmetric(AsymmetricNonces::SodiumOxide(nonce.to_owned())),
        //             public_key: public_key.to_owned(),
        //         },
        //     )),
        // })
    }

    /// Decrypts the given ciphertext using this secret and a given public key, along with
    /// the nonce using during encryption. The provided public key is permitted to be the
    /// public key associated with this secret key.
    pub fn try_unseal(
        &self,
        public_key: &SodiumOxidePublicAsymmetricKey,
        sealed_source: &BytesSources,
        nonce: &AsymmetricNonce,
    ) -> Result<VectorBytesSource, CryptoError> {
        let ciphertext = sealed_source.get()?;
        let precomputed_key = box_::precompute(&public_key.key, &self.key);
        Ok(VectorBytesSource::new(Some(
            box_::open_precomputed(ciphertext, &nonce.nonce, &precomputed_key)
                .map_err(|_| CryptoError::CiphertextFailedVerification)?
                .as_ref(),
        )))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicAsymmetricKey {
    pub key: ExternalPublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicAsymmetricKeyReference {
    pub name: KeyName,
}

// impl TryFrom<Types> for SodiumOxidePublicAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(value: Types) -> Result<Self, Self::Error> {
//         match value {
//             Types::Keys(KeyTypes::Asymmetric(AsymmetricKeyTypes::Public(
//                 PublicAsymmetricKeyTypes::SodiumOxide(SodiumOxidePublicAsymmetricKeys::Unsealed(
//                     usosak,
//                 )),
//             ))) => Ok(usosak),
//             _ => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub enum SodiumOxidePublicAsymmetricKeys {
//     Sealed(SealedSodiumOxidePublicAsymmetricKey),
//     Unsealed(SodiumOxidePublicAsymmetricKey),
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedSodiumOxidePublicAsymmetricKey {
    pub source: BytesSources,
    pub unsealedby: KeyTypeReferences,
}

// impl TryFrom<Types> for SealedSodiumOxidePublicAsymmetricKey {
//     type Error = CryptoError;

//     fn try_from(value: Types) -> Result<Self, Self::Error> {
//         match value {
//             Types::Keys(KeyTypes::Asymmetric(AsymmetricKeyTypes::Public(
//                 PublicAsymmetricKeyTypes::SodiumOxide(SodiumOxidePublicAsymmetricKeys::Sealed(
//                     ssosak,
//                 )),
//             ))) => Ok(ssosak),
//             _ => Err(CryptoError::NotDowncastable),
//         }
//     }
// }

impl SodiumOxidePublicAsymmetricKey {
    /// Encrypts the given plaintext using this public key and a given secret key. The given
    /// secret key is permitted to be the secret key associated with this public key.
    pub fn try_seal(
        &self,
        secret_key: &SodiumOxideSecretAsymmetricKey,
        plaintext: &BytesSources,
        nonce: Option<&AsymmetricNonce>,
    ) -> Result<VectorBytesSource, CryptoError> {
        let precomputed_key = box_::precompute(&self.key, &secret_key.key);
        let nonce = match nonce {
            Some(nonce) => nonce.clone(),
            None => AsymmetricNonce {
                nonce: box_::gen_nonce(),
            },
        };

        Ok(VectorBytesSource::new(Some(
            box_::seal_precomputed(&plaintext.get()?, &nonce.nonce, &precomputed_key).as_ref(),
        )))
        // Ok(SealedSource {
        //     source: Sources::Bytes(BytesSources::Vector(vbs)),
        //     decryptedby: UnsealKeyRefs::Asymmetric(AsymmetricDecryptionKeyRefs::SodiumOxide(
        //         AsymmetricDecryptionKeyRef {
        //             name: secret_key.name().to_owned(),
        //             nonce: Nonces::Asymmetric(AsymmetricNonces::SodiumOxide(nonce.to_owned())),
        //             public_key: self.to_owned(),
        //         },
        //     )),
        // })
    }

    /// Decrypts the given ciphertext using a given secret key and this public key, along with
    /// the nonce using during encryption. The provided secret key is permitted to be the
    /// secret key associated with this public key.
    pub fn try_unseal(
        &self,
        secret_key: &SodiumOxideSecretAsymmetricKey,
        sealed_source: &BytesSources,
        nonce: &AsymmetricNonce,
    ) -> Result<VectorBytesSource, CryptoError> {
        let ciphertext = sealed_source.get()?;
        let precomputed_key = box_::precompute(&self.key, &secret_key.key);
        Ok(VectorBytesSource::new(Some(
            box_::open_precomputed(ciphertext, &nonce.nonce, &precomputed_key)
                .map_err(|_| CryptoError::CiphertextFailedVerification)?
                .as_ref(),
        )))
    }
}
