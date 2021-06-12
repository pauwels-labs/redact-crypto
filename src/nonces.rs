pub mod sodiumoxide;

use crate::nonces::sodiumoxide::{
    AsymmetricNonce as SodiumOxideAsymmetricNonce, SymmetricNonce as SodiumOxideSymmetricNonce,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Nonces {
    Symmetric(SymmetricNonces),
    Asymmetric(AsymmetricNonces),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SymmetricNonces {
    SodiumOxide(SodiumOxideSymmetricNonce),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AsymmetricNonces {
    SodiumOxide(SodiumOxideAsymmetricNonce),
}
