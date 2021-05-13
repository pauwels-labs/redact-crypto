use crate::{
    error::CryptoError,
    key_sources::{BytesKeySources, KeySources, VectorBytesKeySource},
};
use serde::{
    de::{self, Deserialize as DeserializeTrait, Deserializer, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use sodiumoxide::crypto::{
    box_::{
        self,
        curve25519xsalsa20poly1305::{PublicKey, SecretKey},
    },
    secretbox::{self, xsalsa20poly1305::Key as SoKey},
};
use std::convert::{TryFrom, TryInto};
use std::fmt;

pub trait SymmetricKeyEncryptor {
    fn try_encrypt(
        &self,
        key_source: &KeySources,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

pub trait AsymmetricKeyEncryptor {
    fn try_encrypt(
        &self,
        key_source: &KeySources,
        public_ks: &KeySources,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeysCollection {
    pub results: Vec<KeyExecutors>,
}

pub struct KeyCollection {
    pub results: Vec<Key>,
}

pub struct Key {
    pub name: String,
    pub executor: KeyExecutors,
    pub source: KeySources,
    pub alg: String,
    pub encrypted_by: Option<String>,
}

impl Key {
    pub fn new(
        name: String,
        executor: KeyExecutors,
        source: KeySources,
        alg: String,
        encrypted_by: Option<String>,
    ) -> Result<Self, CryptoError> {
        Ok(Key {
            name,
            executor,
            source,
            alg,
            encrypted_by,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn executor(&self) -> &KeyExecutors {
        &self.executor
    }

    pub fn source(&self) -> &KeySources {
        &self.source
    }

    pub fn encrypted_by(&self) -> &Option<String> {
        &self.encrypted_by
    }

    pub fn alg(&self) -> &str {
        &self.alg
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyExecutors {
    Symmetric(SymmetricKeyExecutors),
    Asymmetric(AsymmetricKeyExecutors),
}

// impl KeyExecutors {
//     pub fn name(&self) -> &str {
//         match self {
//             Self::Symmetric(sk) => &sk.name(),
//             Self::Asymmetric(ak) => &ak.name(),
//         }
//     }

//     pub fn source(&self) -> &KeySources {
//         match self {
//             Self::Symmetric(sk) => &sk.source(),
//             Self::Asymmetric(ak) => &ak.source(),
//         }
//     }

//     pub fn encrypted_by(&self) -> &Option<String> {
//         match self {
//             Self::Symmetric(sk) => &sk.encrypted_by(),
//             Self::Asymmetric(ak) => &ak.encrypted_by(),
//         }
//     }

//     pub fn alg(&self) -> &str {
//         match self {
//             Self::Symmetric(sk) => &sk.alg(),
//             Self::Asymmetric(ak) => &ak.alg(),
//         }
//     }
// }

// impl TryFrom<KeyExecutors> for SymmetricKeyExecutors {
//     type Error = CryptoError;

//     fn try_from(key: KeyExecutors) -> Result<Self, Self::Error> {
//         match key {
//             KeyExecutors::Symmetric(sk) => Ok(sk),
//             _ => Err(CryptoError::NotSymmetric),
//         }
//     }
// }

// impl TryFrom<KeyExecutors> for AsymmetricKeyExecutors {
//     type Error = CryptoError;

//     fn try_from(key: KeyExecutors) -> Result<Self, Self::Error> {
//         match key {
//             KeyExecutors::Asymmetric(ak) => Ok(ak),
//             _ => Err(CryptoError::NotAsymmetric),
//         }
//     }
// }

// impl TryFrom<KeyExecutors> for SecretKeyExecutors {
//     type Error = CryptoError;

//     fn try_from(key: KeyExecutors) -> Result<Self, Self::Error> {
//         let asym_key: AsymmetricKeyExecutors = key.try_into()?;
//         asym_key.try_into()
//     }
// }

// impl TryFrom<KeyExecutors> for PublicKeyExecutors {
//     type Error = CryptoError;

//     fn try_from(key: KeyExecutors) -> Result<Self, Self::Error> {
//         let asym_key: AsymmetricKeyExecutors = key.try_into()?;
//         asym_key.try_into()
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SymmetricKeyExecutors {
    SodiumOxide(SodiumOxideSymmetricKeyExecutor),
}

// impl SymmetricKeyExecutors {
//     pub fn name(&self) -> &str {
//         match self {
//             Self::SodiumOxide(sosk) => &sosk.name(),
//         }
//     }

//     pub fn source(&self) -> &KeySources {
//         match self {
//             Self::SodiumOxide(sosk) => &sosk.source(),
//         }
//     }

//     pub fn encrypted_by(&self) -> &Option<String> {
//         match self {
//             Self::SodiumOxide(sosk) => &sosk.encrypted_by(),
//         }
//     }

//     pub fn alg(&self) -> &str {
//         match self {
//             Self::SodiumOxide(sosk) => &sosk.alg(),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricKeyExecutor {}

// impl SodiumOxideSymmetricKeyExecutor {
//     pub fn name(&self) -> &str {
//         &self.name
//     }

//     pub fn source(&self) -> &KeySources {
//         &self.source
//     }

//     pub fn encrypted_by(&self) -> &Option<String> {
//         &self.encrypted_by
//     }

//     pub fn alg(&self) -> &str {
//         &self.alg
//     }
// }

impl SymmetricKeyEncryptor for SodiumOxideSymmetricKeyExecutor {
    fn try_encrypt(
        &self,
        key_source: &KeySources,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key_source: BytesKeySources = key_source.clone().try_into()?;
        let key_bytes = key_source.get()?;
        let key: SoKey = SoKey::from_slice(key_bytes).ok_or(CryptoError::SourceKeyBadSize)?;
        let nonce = secretbox::gen_nonce();
        Ok(secretbox::seal(plaintext, &nonce, &key))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AsymmetricKeyExecutors {
    Public(PublicKeyExecutors),
    Secret(SecretKeyExecutors),
}

// impl AsymmetricKeyExecutors {
//     pub fn name(&self) -> &str {
//         match self {
//             Self::Public(pk) => &pk.name(),
//             Self::Secret(sk) => &sk.name(),
//         }
//     }

//     pub fn source(&self) -> &KeySources {
//         match self {
//             Self::Public(pk) => &pk.source(),
//             Self::Secret(sk) => &sk.source(),
//         }
//     }

//     pub fn encrypted_by(&self) -> &Option<String> {
//         match self {
//             Self::Public(pk) => &pk.encrypted_by(),
//             Self::Secret(sk) => &sk.encrypted_by(),
//         }
//     }

//     pub fn alg(&self) -> &str {
//         match self {
//             Self::Public(pk) => &pk.alg(),
//             Self::Secret(sk) => &sk.alg(),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PublicKeyExecutors {
    SodiumOxide(SodiumOxidePublicKeyExecutor),
}

// impl PublicKeyExecutors {
//     pub fn name(&self) -> &str {
//         match self {
//             Self::SodiumOxide(sopk) => &sopk.name(),
//         }
//     }

//     pub fn source(&self) -> &KeySources {
//         match self {
//             Self::SodiumOxide(sopk) => &sopk.source(),
//         }
//     }

//     pub fn encrypted_by(&self) -> &Option<String> {
//         match self {
//             Self::SodiumOxide(sopk) => &sopk.encrypted_by(),
//         }
//     }

//     pub fn alg(&self) -> &str {
//         match self {
//             Self::SodiumOxide(sopk) => &sopk.alg(),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SecretKeyExecutors {
    SodiumOxide(SodiumOxideSecretKeyExecutor),
}

// impl SecretKeyExecutors {
//     pub fn name(&self) -> &str {
//         match self {
//             Self::SodiumOxide(sosk) => &sosk.name(),
//         }
//     }

//     pub fn source(&self) -> &KeySources {
//         match self {
//             Self::SodiumOxide(sosk) => &sosk.source(),
//         }
//     }

//     pub fn encrypted_by(&self) -> &Option<String> {
//         match self {
//             Self::SodiumOxide(sosk) => &sosk.encrypted_by(),
//         }
//     }

//     pub fn alg(&self) -> &str {
//         match self {
//             Self::SodiumOxide(sosk) => &sosk.alg(),
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxidePublicKeyExecutor {}

// impl SodiumOxidePublicKeyExecutor {
//     pub fn name(&self) -> &str {
//         &self.name
//     }

//     pub fn source(&self) -> &KeySources {
//         &self.source
//     }

//     pub fn encrypted_by(&self) -> &Option<String> {
//         &self.encrypted_by
//     }

//     pub fn alg(&self) -> &str {
//         &self.alg
//     }
// }

// impl TryFrom<AsymmetricKeyExecutors> for SecretKeyExecutors {
//     type Error = CryptoError;

//     fn try_from(ak: AsymmetricKeyExecutors) -> Result<Self, Self::Error> {
//         match ak {
//             AsymmetricKeyExecutors::Secret(sk) => Ok(sk),
//             _ => Err(CryptoError::NotSecret),
//         }
//     }
// }

// impl TryFrom<AsymmetricKeyExecutors> for PublicKeyExecutors {
//     type Error = CryptoError;

//     fn try_from(ak: AsymmetricKeyExecutors) -> Result<Self, Self::Error> {
//         match ak {
//             AsymmetricKeyExecutors::Secret(sk) => sk.try_into(),
//             AsymmetricKeyExecutors::Public(pk) => Ok(pk),
//         }
//     }
// }

// impl TryFrom<SecretKeyExecutors> for PublicKeyExecutors {
//     type Error = CryptoError;

//     fn try_from(sk: SecretKeyExecutors) -> Result<Self, Self::Error> {
//         match sk {
//             SecretKeyExecutors::SodiumOxide(sosk) => {
//                 let secret_key = SecretKey::from_slice(
//                     TryInto::<BytesKeySources>::try_into(sosk.source)?.get()?,
//                 )
//                 .ok_or(CryptoError::SourceKeyBadSize)?;
//                 let public_key = secret_key.public_key();
//                 let vbks = VectorBytesKeySource::new(Some(public_key.as_ref()));

//                 Ok(PublicKeyExecutors::SodiumOxide(
//                     SodiumOxidePublicKeyExecutor {
//                         source: KeySources::Bytes(BytesKeySources::Vector(vbks)),
//                         alg: "curve25519xsalsa20poly1305".to_owned(),
//                         encrypted_by: None,
//                         name: sosk.name,
//                     },
//                 ))
//             }
//         }
//     }
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSecretKeyExecutor {}

impl AsymmetricKeyEncryptor for SecretKeyExecutors {
    fn try_encrypt(
        &self,
        key_source: &KeySources,
        public_ks: &KeySources,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match self {
            SecretKeyExecutors::SodiumOxide(sosk) => {
                sosk.try_encrypt(key_source, public_ks, plaintext)
            }
        }
    }
}

// impl TryFrom<SodiumOxideSecretKeyExecutor> for SodiumOxidePublicKeyExecutor {
//     type Error = CryptoError;

//     fn try_from(sosk: SodiumOxideSecretKeyExecutor) -> Result<Self, Self::Error> {
//         let bks: BytesKeySources = sosk.source.try_into()?;
//         let secret_key_bytes = bks.get()?;

//         let secret_key =
//             SecretKey::from_slice(secret_key_bytes).ok_or(CryptoError::SourceKeyBadSize)?;
//         let public_key = secret_key.public_key();
//         Ok(SodiumOxidePublicKeyExecutor {
//             source: KeySources::Bytes(BytesKeySources::Vector(VectorBytesKeySource::new(Some(
//                 public_key.as_ref(),
//             )))),
//             alg: "curve25519xsalsa20poly1305".to_owned(),
//             encrypted_by: None,
//             name: sosk.name,
//         })
//     }
// }

impl SodiumOxideSecretKeyExecutor {
    // pub fn name(&self) -> &str {
    //     &self.name
    // }

    // pub fn source(&self) -> &KeySources {
    //     &self.source
    // }

    // pub fn encrypted_by(&self) -> &Option<String> {
    //     &self.encrypted_by
    // }

    // pub fn alg(&self) -> &str {
    //     &self.alg
    // }

    // pub fn new(
    //     name: &str,
    //     source: KeySources,
    //     alg: &str,
    //     encrypted_by: Option<String>,
    // ) -> Result<Self, CryptoError> {
    //     let mut bks: BytesKeySources = source.try_into()?;
    //     match bks.get() {
    //         Ok(_) => Ok(SodiumOxideSecretKeyExecutor {
    //             name: name.to_owned(),
    //             source: KeySources::Bytes(bks),
    //             alg: alg.to_owned(),
    //             encrypted_by,
    //         }),
    //         Err(e) => match e {
    //             CryptoError::NotFound => {
    //                 let (_, sk) = box_::gen_keypair();
    //                 bks.set(sk.as_ref())?;
    //                 Ok(SodiumOxideSecretKeyExecutor {
    //                     name: name.to_owned(),
    //                     source: KeySources::Bytes(bks),
    //                     alg: alg.to_owned(),
    //                     encrypted_by,
    //                 })
    //             }
    //             _ => Err(e),
    //         },
    //     }
    // }
}

impl AsymmetricKeyEncryptor for SodiumOxideSecretKeyExecutor {
    fn try_encrypt(
        &self,
        key_source: &KeySources,
        public_ks: &KeySources,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let secret_bks: BytesKeySources = key_source.clone().try_into()?;
        let public_bks: BytesKeySources = public_ks.clone().try_into()?;
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

// impl<'de> DeserializeTrait<'de> for SodiumOxideSecretKeyExecutor {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         enum Field {
//             Source,
//             Alg,
//             EncryptedBy,
//             Name,
//         }

//         impl<'de> Deserialize<'de> for Field {
//             fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
//             where
//                 D: Deserializer<'de>,
//             {
//                 struct FieldVisitor;

//                 impl<'de> Visitor<'de> for FieldVisitor {
//                     type Value = Field;

//                     fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                         formatter.write_str("`source` or `alg` or `encrypted_by` or `name`")
//                     }

//                     fn visit_str<E>(self, value: &str) -> Result<Field, E>
//                     where
//                         E: de::Error,
//                     {
//                         match value {
//                             "source" => Ok(Field::Source),
//                             "alg" => Ok(Field::Alg),
//                             "encrypted_by" => Ok(Field::EncryptedBy),
//                             "name" => Ok(Field::Name),
//                             _ => Err(de::Error::unknown_field(value, FIELDS)),
//                         }
//                     }
//                 }

//                 deserializer.deserialize_identifier(FieldVisitor)
//             }
//         }

//         struct SodiumOxideSecretKeyVisitor;

//         impl<'de> Visitor<'de> for SodiumOxideSecretKeyVisitor {
//             type Value = SodiumOxideSecretKeyExecutor;

//             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                 formatter.write_str("struct SodiumOxideSecretKey")
//             }

//             fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
//             where
//                 V: SeqAccess<'de>,
//             {
//                 let source: KeySources = seq
//                     .next_element()?
//                     .ok_or_else(|| de::Error::invalid_length(0, &self))?;
//                 let alg = seq
//                     .next_element()?
//                     .ok_or_else(|| de::Error::invalid_length(0, &self))?;
//                 let encrypted_by = seq
//                     .next_element()?
//                     .ok_or_else(|| de::Error::invalid_length(0, &self))?;
//                 let name = seq
//                     .next_element()?
//                     .ok_or_else(|| de::Error::invalid_length(0, &self))?;

//                 SodiumOxideSecretKeyExecutor::new(name, source, alg, encrypted_by)
//                     .map_err(de::Error::custom)
//             }

//             fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
//             where
//                 V: MapAccess<'de>,
//             {
//                 let mut source = None;
//                 let mut name: Option<String> = None;
//                 let mut alg: Option<String> = None;
//                 let mut encrypted_by: Option<String> = None;

//                 while let Some(key) = map.next_key()? {
//                     match key {
//                         Field::Source => {
//                             if source.is_some() {
//                                 return Err(de::Error::duplicate_field("source"));
//                             }
//                             source = Some(map.next_value()?);
//                         }
//                         Field::Alg => {
//                             if alg.is_some() {
//                                 return Err(de::Error::duplicate_field("alg"));
//                             }
//                             alg = Some(map.next_value()?);
//                         }
//                         Field::EncryptedBy => {
//                             if encrypted_by.is_some() {
//                                 return Err(de::Error::duplicate_field("encrypted_by"));
//                             }
//                             let next_result = map.next_value();
//                             encrypted_by = Some(next_result?);
//                         }
//                         Field::Name => {
//                             if name.is_some() {
//                                 return Err(de::Error::duplicate_field("name"));
//                             }
//                             name = Some(map.next_value()?);
//                         }
//                     }
//                 }
//                 let source = source.ok_or_else(|| de::Error::missing_field("source"))?;
//                 let alg = alg.ok_or_else(|| de::Error::missing_field("alg"))?;
//                 let name = name.ok_or_else(|| de::Error::missing_field("name"))?;
//                 SodiumOxideSecretKeyExecutor::new(&name, source, &alg, encrypted_by)
//                     .map_err(de::Error::custom)
//             }
//         }

//         const FIELDS: &'static [&'static str] = &["source", "alg", "encrypted_by", "name"];
//         deserializer.deserialize_struct("SodiumOxideSecretKey", FIELDS, SodiumOxideSecretKeyVisitor)
//     }
// }
