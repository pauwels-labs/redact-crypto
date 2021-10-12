use crate::{CryptoError, Entry, NonIndexedTypeStorer, StorableType, Storer, TypeStorer};
use async_trait::async_trait;
use cloud_storage::Client;
use cloud_storage::Error::Other;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

#[derive(Debug)]
pub enum GoogleCloudStorerError {
    /// Represents an error which occurred in some internal system
    InternalError {
        source: Box<dyn Error + Send + Sync>,
    },

    /// Requested document was not found
    NotFound,
}

impl Error for GoogleCloudStorerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            GoogleCloudStorerError::InternalError { ref source } => Some(source.as_ref()),
            GoogleCloudStorerError::NotFound => None,
        }
    }
}

impl Display for GoogleCloudStorerError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            GoogleCloudStorerError::InternalError { .. } => {
                write!(f, "Internal error occurred")
            }
            GoogleCloudStorerError::NotFound => {
                write!(f, "Requested document not found")
            }
        }
    }
}

impl From<GoogleCloudStorerError> for CryptoError {
    fn from(gcse: GoogleCloudStorerError) -> Self {
        match gcse {
            GoogleCloudStorerError::InternalError { .. } => CryptoError::InternalError {
                source: Box::new(gcse),
            },
            GoogleCloudStorerError::NotFound => CryptoError::NotFound {
                source: Box::new(gcse),
            },
        }
    }
}

/// Stores an instance of a mongodb-backed key storer
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GoogleCloudStorer {
    bucket_name: String,
}

impl From<GoogleCloudStorer> for NonIndexedTypeStorer {
    fn from(gcs: GoogleCloudStorer) -> Self {
        NonIndexedTypeStorer::GoogleCloud(gcs)
    }
}

impl From<GoogleCloudStorer> for TypeStorer {
    fn from(gcs: GoogleCloudStorer) -> Self {
        TypeStorer::NonIndexed(NonIndexedTypeStorer::GoogleCloud(gcs))
    }
}

impl GoogleCloudStorer {
    pub fn new(bucket_name: String) -> Self {
        GoogleCloudStorer { bucket_name }
    }
}

#[async_trait]
impl Storer for GoogleCloudStorer {
    async fn get<T: StorableType>(&self, path: &str) -> Result<Entry<T>, CryptoError> {
        let client = Client::new();
        let bytes = client
            .object()
            .download(&self.bucket_name, path)
            .await
            .map_err(|e| match e {
                Other(_) => GoogleCloudStorerError::NotFound {},
                _ => GoogleCloudStorerError::InternalError {
                    source: Box::new(e),
                },
            })?;

        let s = String::from_utf8(bytes).map_err(|e| GoogleCloudStorerError::InternalError {
            source: Box::new(e),
        })?;

        Ok(
            serde_json::from_str(&s).map_err(|e| GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            })?,
        )
    }

    async fn create<T: StorableType>(&self, entry: Entry<T>) -> Result<Entry<T>, CryptoError> {
        let entry_string =
            serde_json::to_string(&entry).map_err(|e| GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            })?;
        let client = Client::new();

        match client
            .object()
            .create(
                &self.bucket_name,
                entry_string.as_bytes().to_vec(),
                &entry.path.clone(),
                "application/json",
            )
            .await
        {
            Ok(_) => Ok(entry),
            Err(e) => Err(GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            }
            .into()),
        }
    }
}
