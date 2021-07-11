//! Classifies nonces used by different key types.

pub mod sodiumoxide;

use self::sodiumoxide::{SodiumOxideSymmetricNonce, SodiumOxideAsymmetricNonce};
use serde::{Deserialize, Serialize};

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
