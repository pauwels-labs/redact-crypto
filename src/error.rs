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
}

impl Error for CryptoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            CryptoError::FsIoError { ref source } => Some(source),
            CryptoError::SourceKeyBadSize => None,
            CryptoError::NotSymmetric => None,
            CryptoError::NotAsymmetric => None,
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
        }
    }
}
