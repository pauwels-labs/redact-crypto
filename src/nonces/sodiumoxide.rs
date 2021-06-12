use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_::{self, Nonce as ExternalAsymmetricNonce, NONCEBYTES as EXTERNALASYMMETRICNONCEBYTES},
    secretbox::{self, Nonce as ExternalSymmetricNonce, NONCEBYTES as EXTERNALSYMMETRICNONCEBYTES},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SymmetricNonce {
    pub nonce: ExternalSymmetricNonce,
}

impl SymmetricNonce {
    pub const NONCEBYTES: usize = EXTERNALSYMMETRICNONCEBYTES;

    pub fn from_slice(bs: &[u8]) -> Option<Self> {
        Some(SymmetricNonce {
            nonce: ExternalSymmetricNonce::from_slice(bs)?,
        })
    }

    pub fn new() -> Self {
        SymmetricNonce {
            nonce: secretbox::gen_nonce(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsymmetricNonce {
    pub nonce: ExternalAsymmetricNonce,
}

impl AsymmetricNonce {
    pub const NONCEBYTES: usize = EXTERNALASYMMETRICNONCEBYTES;

    pub fn from_slice(bs: &[u8]) -> Option<Self> {
        Some(AsymmetricNonce {
            nonce: ExternalAsymmetricNonce::from_slice(bs)?,
        })
    }

    pub fn new() -> Self {
        AsymmetricNonce {
            nonce: box_::gen_nonce(),
        }
    }
}
