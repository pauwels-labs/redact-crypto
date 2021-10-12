use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sodiumoxide::crypto::{
    box_::{self, Nonce as ExternalAsymmetricNonce, NONCEBYTES as EXTERNALASYMMETRICNONCEBYTES},
    secretbox::{self, Nonce as ExternalSymmetricNonce, NONCEBYTES as EXTERNALSYMMETRICNONCEBYTES},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideSymmetricNonce {
    #[serde(
        serialize_with = "symmetric_nonce_serialize",
        deserialize_with = "symmetric_nonce_deserialize"
    )]
    pub nonce: ExternalSymmetricNonce,
}

/// Custom serialization function base64-encodes the bytes before storage
fn symmetric_nonce_serialize<S>(nonce: &ExternalSymmetricNonce, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let b64_encoded = base64::encode(nonce.as_ref());
    s.serialize_some(&Some(b64_encoded))
}

/// Custom deserialization function base64-decodes the bytes before passing them back
fn symmetric_nonce_deserialize<'de, D>(deserializer: D) -> Result<ExternalSymmetricNonce, D::Error>
where
    D: Deserializer<'de>,
{
    let b64_encoded: String = de::Deserialize::deserialize(deserializer)?;
    let decoded = base64::decode(b64_encoded).map_err(de::Error::custom)?;
    let nonce = ExternalSymmetricNonce::from_slice(decoded.as_ref());
    match nonce {
        Some(n) => Ok(n),
        None => Err(de::Error::custom(format!(
            "deserialized nonce was {} bytes long, expected 24 bytes",
            decoded.len()
        ))),
    }
}

impl SodiumOxideSymmetricNonce {
    pub const NONCEBYTES: usize = EXTERNALSYMMETRICNONCEBYTES;

    pub fn from_slice(bs: &[u8]) -> Option<Self> {
        Some(SodiumOxideSymmetricNonce {
            nonce: ExternalSymmetricNonce::from_slice(bs)?,
        })
    }

    pub fn new() -> Self {
        SodiumOxideSymmetricNonce {
            nonce: secretbox::gen_nonce(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideAsymmetricNonce {
    #[serde(
        serialize_with = "asymmetric_nonce_serialize",
        deserialize_with = "asymmetric_nonce_deserialize"
    )]
    pub nonce: ExternalAsymmetricNonce,
}

/// Custom serialization function base64-encodes the bytes before storage
fn asymmetric_nonce_serialize<S>(nonce: &ExternalAsymmetricNonce, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let b64_encoded = base64::encode(nonce.as_ref());
    s.serialize_some(&Some(b64_encoded))
}

/// Custom deserialization function base64-decodes the bytes before passing them back
fn asymmetric_nonce_deserialize<'de, D>(
    deserializer: D,
) -> Result<ExternalAsymmetricNonce, D::Error>
where
    D: Deserializer<'de>,
{
    let b64_encoded: String = de::Deserialize::deserialize(deserializer)?;
    let decoded = base64::decode(b64_encoded).map_err(de::Error::custom)?;
    let nonce = ExternalAsymmetricNonce::from_slice(decoded.as_ref());
    match nonce {
        Some(n) => Ok(n),
        None => Err(de::Error::custom(format!(
            "deserialized nonce was {} bytes long, expected 24 bytes",
            decoded.len()
        ))),
    }
}

impl SodiumOxideAsymmetricNonce {
    pub const NONCEBYTES: usize = EXTERNALASYMMETRICNONCEBYTES;

    pub fn from_slice(bs: &[u8]) -> Option<Self> {
        Some(SodiumOxideAsymmetricNonce {
            nonce: ExternalAsymmetricNonce::from_slice(bs)?,
        })
    }

    pub fn new() -> Self {
        SodiumOxideAsymmetricNonce {
            nonce: box_::gen_nonce(),
        }
    }
}
