//! CryptoError covers all errors not covered by StorageError. It is returned by
//! every function in this crate returning a Result except those used in the
//! `Storer` trait.

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

/// Error that wraps all possible errors out of the redact-crypto crate
#[derive(Debug)]
pub enum CryptoError {
    /// Represents an error which occurred in some internal system
    InternalError {
        source: Box<dyn Error + Send + Sync>,
    },

    /// The requested resource was not found
    NotFound {
        source: Box<dyn Error + Send + Sync>,
    },

    /// Ciphertext failed veri fication before decryption
    CiphertextFailedVerification,

    /// Provided bytes are not the right length for the key
    InvalidKeyLength { expected: usize, actual: usize },

    /// Provided bytes are not the right length for the seed
    InvalidSeedLength { expected: usize, actual: usize },

    /// Given value was not of the right type to be downcasted to the requested type
    NotDowncastable,

    /// Given bytes could not be serialized to a base data type
    NotDeserializableToBaseDataType,

    /// Wrong nonce was provided during seal/unseal operation
    WrongNonceType,

    /// The method is not implemented for the storage implementation
    NotImplemented
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            CryptoError::InternalError { ref source } => Some(source.as_ref()),
            CryptoError::NotFound { ref source } => Some(source.as_ref()),
            CryptoError::CiphertextFailedVerification => None,
            CryptoError::InvalidKeyLength { .. } => None,
            CryptoError::InvalidSeedLength { .. } => None,
            CryptoError::NotDowncastable => None,
            CryptoError::NotDeserializableToBaseDataType => None,
            CryptoError::WrongNonceType => None,
            CryptoError::NotImplemented => None,
        }
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            CryptoError::InternalError { .. } => {
                write!(f, "Internal error occurred")
            }
            CryptoError::NotFound { .. } => {
                write!(f, "Requested resource not found")
            }
            CryptoError::CiphertextFailedVerification => {
                write!(f, "Ciphertext failed verification before decryption")
            }
            CryptoError::InvalidKeyLength {
                ref expected,
                ref actual,
            } => {
                write!(
                    f,
                    "Provided key was not the correct length, expected: {}, actual: {}",
                    expected, actual,
                )
            }
            CryptoError::InvalidSeedLength {
                ref expected,
                ref actual,
            } => {
                write!(
                    f,
                    "Provided seed was not the correct length, expected: {}, actual: {}",
                    expected, actual,
                )
            }
            CryptoError::NotDowncastable => {
                write!(
                    f,
                    "Could not downcast the Types-value into the requested variant"
                )
            }
            CryptoError::NotDeserializableToBaseDataType => {
                write!(f, "Given bytes could not be deserialized to one of: bool, u64, i64, f64, or string")
            }
            CryptoError::WrongNonceType => {
                write!(f, "Invalid type of nonce was provided for the operation")
            }
            CryptoError::NotImplemented => {
                write!(f, "The method is not implemented for the storage implementation")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CryptoError;

    #[test]
    fn test_to_string_internal_error() {
        let s = CryptoError::InternalError {
            source: Box::new(CryptoError::NotDowncastable),
        }
        .to_string();
        assert_eq!(s, "Internal error occurred");
    }

    #[test]
    fn test_to_string_not_found() {
        let s = CryptoError::NotDowncastable.to_string();
        assert_eq!(
            s,
            "Could not downcast the Types-value into the requested variant"
        );
    }
}
