//! CryptoError covers all errors not covered by StorageError. It is returned by
//! every function in this crate returning a Result except those used in the
//! `Storer` trait.

use base64::DecodeError;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io,
};

/// Error that wraps all possible errors out of the redact-crypto crate
#[derive(Debug)]
pub enum CryptoError {
    /// Represents an error which occurred in some internal system
    InternalError {
        source: Box<dyn Error + Send + Sync>,
    },

    /// Error occurred while performing IO on the filesystem
    FsIoError { source: io::Error },

    /// File path given was not found
    FileNotFound { path: String },

    /// The requested resource was not found
    NotFound,

    /// Ciphertext failed veri fication before decryption
    CiphertextFailedVerification,

    /// Provided bytes are not the right length for the
    InvalidKeyLength { expected: usize, actual: usize },

    /// Given value was not of the right type to be downcasted to the requested type
    NotDowncastable,

    /// File path given has an invalid file name with no stem
    FilePathHasNoFileStem { path: String },

    /// File path given was invalid UTF-8
    FilePathIsInvalidUTF8,

    /// Given bytes could not be serialized to a base data type
    NotDeserializableToBaseDataType,

    /// Error happened when decoding base64 string
    Base64Decode { source: DecodeError },

    /// Wrong nonce was provided during seal/unseal operation
    WrongNonceType,
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            CryptoError::InternalError { ref source } => Some(source.as_ref()),
            CryptoError::FsIoError { ref source } => Some(source),
            CryptoError::FileNotFound { .. } => None,
            CryptoError::NotFound => None,
            CryptoError::CiphertextFailedVerification => None,
            CryptoError::InvalidKeyLength { .. } => None,
            CryptoError::NotDowncastable => None,
            CryptoError::FilePathHasNoFileStem { .. } => None,
            CryptoError::FilePathIsInvalidUTF8 => None,
            CryptoError::NotDeserializableToBaseDataType => None,
            CryptoError::Base64Decode { ref source } => Some(source),
            CryptoError::WrongNonceType => None,
        }
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            CryptoError::InternalError { .. } => {
                write!(f, "Internal error occurred")
            }
            CryptoError::FsIoError { .. } => {
                write!(f, "Error occured during file system IO")
            }
            CryptoError::FileNotFound { ref path } => {
                write!(f, "Path \"{}\" not found", path)
            }
            CryptoError::NotFound => {
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
            CryptoError::NotDowncastable => {
                write!(
                    f,
                    "Could not downcast the Types-value into the requested variant"
                )
            }
            CryptoError::FilePathHasNoFileStem { ref path } => {
                write!(
                    f,
                    "File path \"{}\" was invalid as the file name has no stem",
                    path
                )
            }
            CryptoError::FilePathIsInvalidUTF8 => {
                write!(f, "Given file path was not valid UTF-8")
            }
            CryptoError::NotDeserializableToBaseDataType => {
                write!(f, "Given bytes could not be deserialized to one of: bool, u64, i64, f64, or string")
            }
            CryptoError::Base64Decode { .. } => {
                write!(f, "Error occurred while decoding string from base64")
            }
            CryptoError::WrongNonceType => {
                write!(f, "Invalid type of nonce was provided for the operation")
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
            source: Box::new(CryptoError::NotFound),
        }
        .to_string();
        assert_eq!(s, "Internal error occurred");
    }

    #[test]
    fn test_to_string_not_found() {
        let s = CryptoError::NotFound.to_string();
        assert_eq!(s, "Requested resource not found");
    }
}
