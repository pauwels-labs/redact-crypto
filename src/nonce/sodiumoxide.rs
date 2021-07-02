use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_::{self, Nonce as ExternalAsymmetricNonce, NONCEBYTES as EXTERNALASYMMETRICNONCEBYTES},
    secretbox::{self, Nonce as ExternalSymmetricNonce, NONCEBYTES as EXTERNALSYMMETRICNONCEBYTES},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiuOxideSymmetricNonce {
    pub nonce: ExternalSymmetricNonce,
}

impl SodiuOxideSymmetricNonce {
    pub const NONCEBYTES: usize = EXTERNALSYMMETRICNONCEBYTES;

    pub fn from_slice(bs: &[u8]) -> Option<Self> {
        Some(SodiuOxideSymmetricNonce {
            nonce: ExternalSymmetricNonce::from_slice(bs)?,
        })
    }

    pub fn new() -> Self {
        SodiuOxideSymmetricNonce {
            nonce: secretbox::gen_nonce(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SodiumOxideAsymmetricNonce {
    pub nonce: ExternalAsymmetricNonce,
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
