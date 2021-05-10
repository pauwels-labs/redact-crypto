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

    /// Indicates the key sources is not a bytes key source but must be
    NotBytesKeySource,
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
            CryptoError::NotBytesKeySource => None,
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
            CryptoError::NotBytesKeySource => {
                write!(f, "The key source was not a bytes key source but must be")
            }
        }
    }
}
