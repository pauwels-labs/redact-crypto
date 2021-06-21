use crate::StorageError;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io,
};

/// Error that wraps all possible errors out of the redact-crypto crate
#[derive(Debug)]
pub enum CryptoError {
    /// Indicates an error occurred while performing IO on the filesystem
    FsIoError { source: io::Error },

    /// Indicates the key loaded key isn't the right size for the selected executor
    SourceKeyBadSize,

    /// Indicates the source key is not a symmetric key
    NotSymmetric,

    /// Indicates the source key is not an asymmetric key
    NotAsymmetric,

    /// Indicates the source key is not a secret asymmetric key
    NotSecret,

    /// This error will never occur
    Infallible,

    /// Indicates the key source could not source the key
    NotFound,

    /// Indicates a ciphertext failed verification before decryption
    CiphertextFailedVerification,

    /// Indicates the provided nonce is not the correct length
    InvalidNonceLength { expected: usize, actual: usize },

    /// Indicates the provided nonce is not the correct length
    InvalidKeyLength { expected: usize, actual: usize },

    /// Indicates the wrong type of key was provided as a parameter
    IncorrectKeyType { expected: String, actual: String },

    /// Wraps a StorageError
    StorageError { source: StorageError },

    /// Indicates a public key was given when a secret key was expected
    ExpectedSecretKey,

    /// Indicates a secret key was given when a public key was expected
    ExpectedPublicKey,

    /// Indicates the wrong type of source was provided during a seal or unseal operation
    IncorrectSourceType {
        expected: String,
        actual: String,
        key: String,
    },

    /// Indicates the wrong type of nonce was provided during a seal or unseal operation
    IncorrectNonceType {
        expected: String,
        actual: String,
        key: String,
    },

    /// Indicates the wrong type of nonce was provided during a seal or unseal operation
    IncorrectSecretKeyType {
        expected: String,
        actual: String,
        key: String,
    },

    /// Indicates the wrong type of nonce was provided during a seal or unseal operation
    IncorrectPublicKeyType {
        expected: String,
        actual: String,
        key: String,
    },

    /// Indicates tried to seal a sealed type
    AlreadySealed,

    /// Indicates the given value was not of the right type to be downcasted to the requested type
    NotDowncastable,

    /// Indicates the file path given has an invalid file name with no stem
    FilePathHasNoFileStem,

    /// Indicates the file path was invalid UTF-8
    FilePathIsInvalidUTF8,
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            CryptoError::FsIoError { ref source } => Some(source),
            CryptoError::SourceKeyBadSize => None,
            CryptoError::NotSymmetric => None,
            CryptoError::NotAsymmetric => None,
            CryptoError::NotSecret => None,
            CryptoError::Infallible => None,
            CryptoError::NotFound => None,
            CryptoError::CiphertextFailedVerification => None,
            CryptoError::InvalidNonceLength { .. } => None,
            CryptoError::InvalidKeyLength { .. } => None,
            CryptoError::IncorrectKeyType { .. } => None,
            CryptoError::StorageError { ref source } => Some(source),
            CryptoError::ExpectedSecretKey => None,
            CryptoError::ExpectedPublicKey => None,
            CryptoError::IncorrectSourceType { .. } => None,
            CryptoError::IncorrectNonceType { .. } => None,
            CryptoError::IncorrectSecretKeyType { .. } => None,
            CryptoError::IncorrectPublicKeyType { .. } => None,
            CryptoError::AlreadySealed => None,
            CryptoError::NotDowncastable => None,
            CryptoError::FilePathHasNoFileStem => None,
            CryptoError::FilePathIsInvalidUTF8 => None,
        }
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            CryptoError::FsIoError { .. } => {
                write!(f, "Error occured during file system IO")
            }
            CryptoError::SourceKeyBadSize => {
                write!(
                    f,
                    "Loaded key is not the correct size for the selected executor"
                )
            }
            CryptoError::NotSymmetric => {
                write!(f, "Key is not a symmetric key")
            }
            CryptoError::NotAsymmetric => {
                write!(f, "Key is not an asymmetric key")
            }
            CryptoError::NotSecret => {
                write!(f, "Key is not a secret asymmetric key")
            }
            CryptoError::Infallible => {
                write!(f, "This error should never occur")
            }
            CryptoError::NotFound => {
                write!(f, "The key source was not found")
            }
            CryptoError::CiphertextFailedVerification => {
                write!(
                    f,
                    "The ciphertext failed verification before attempting to decrypt"
                )
            }
            CryptoError::InvalidNonceLength {
                ref expected,
                ref actual,
            } => {
                write!(
                    f,
                    "The provided nonce was not the correct length, expected: {}, actual: {}",
                    expected, actual,
                )
            }
            CryptoError::InvalidKeyLength {
                ref expected,
                ref actual,
            } => {
                write!(
                    f,
                    "The provided key was not the correct length, expected: {}, actual: {}",
                    expected, actual,
                )
            }
            CryptoError::IncorrectKeyType {
                ref expected,
                ref actual,
            } => {
                write!(
                    f,
                    "The key provided was of an incorrect type, expected: {}, actual: {}",
                    expected, actual,
                )
            }
            CryptoError::StorageError { .. } => {
                write!(f, "Error occured while interacting with key storage")
            }
            CryptoError::ExpectedSecretKey => {
                write!(f, "A public key was given when a secret key was expected")
            }
            CryptoError::ExpectedPublicKey => {
                write!(f, "A secret key was given when a public key was expected")
            }
            CryptoError::IncorrectSourceType { .. } => {
                write!(f, "The source provided for the given key was invalid")
            }
            CryptoError::IncorrectNonceType { .. } => {
                write!(f, "The nonce provided for the given key was invalid")
            }
            CryptoError::IncorrectPublicKeyType { .. } => {
                write!(
                    f,
                    "The public key provided for the given secret key was invalid"
                )
            }
            CryptoError::IncorrectSecretKeyType { .. } => {
                write!(
                    f,
                    "The secret key provided for the given public key was invalid"
                )
            }
            CryptoError::AlreadySealed => {
                write!(f, "The type is already sealed, cannot seal again")
            }
            CryptoError::NotDowncastable => {
                write!(
                    f,
                    "Could not downcast the Types-value into the requested variant"
                )
            }
            CryptoError::FilePathHasNoFileStem => {
                write!(
                    f,
                    "The given file path was invalid as the file name has no stem"
                )
            }
            CryptoError::FilePathIsInvalidUTF8 => {
                write!(f, "The given file path was not valid UTF-8")
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::StorageError;

    #[test]
    fn test_to_string_internal_error() {
        let s = StorageError::InternalError {
            source: Box::new(StorageError::NotFound),
        }
        .to_string();
        assert_eq!(s, "Internal error occurred");
    }

    #[test]
    fn test_to_string_not_found() {
        let s = StorageError::NotFound.to_string();
        assert_eq!(s, "Key not found");
    }
}
