//! Classifies nonces used by different key types.

pub mod sodiumoxide;

use self::sodiumoxide::{SodiumOxideAsymmetricNonce, SodiumOxideSymmetricNonce};
use serde::{Deserialize, Serialize};

/// Trait indicating a type has a nonce
pub trait HasNonce {
    fn nonce(&self) -> Nonce;
}

/// Highest-level nonce enum splits nonces into symmetric and asymmetric categories
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Nonce {
    Symmetric(SymmetricNonce),
    Asymmetric(AsymmetricNonce),
}

/// Supported nonces used for symmetric encryption
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SymmetricNonce {
    SodiumOxide(SodiumOxideSymmetricNonce),
}

/// Supported nonces used for asymmetric encryption
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AsymmetricNonce {
    SodiumOxide(SodiumOxideAsymmetricNonce),
}
