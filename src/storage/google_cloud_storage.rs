use crate::{CryptoError, Entry, StorableType, Storer, TypeStorer};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};
use mongodb::bson::Document;
use google_cloud::storage::Client;

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
#[derive(Serialize, Deserialize, Debug)]
pub struct GoogleCloudStorer {
    project_name: String,
}

impl From<GoogleCloudStorer> for TypeStorer {
    fn from(gcs: GoogleCloudStorer) -> Self {
        TypeStorer::GoogleCloud(gcs)
    }
}

impl GoogleCloudStorer {
    pub fn new(project_name: String) -> Self {
        return GoogleCloudStorer {
            project_name,
        }
    }
}

impl GoogleCloudStorer {
    async fn get_client(&self) -> Result<Client, GoogleCloudStorerError> {
        Client::new(&self.project_name)
            .await
            .map_err(|e| GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            })
    }
}

#[async_trait]
impl Storer for GoogleCloudStorer {
    async fn get_indexed<T: StorableType>(
        &self,
        path: &str,
        _index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError> {


        let bytes = self.get_client()
            .await?
            .bucket("entries")
            .await
            .map_err(|e| GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            })?
            .object(path)
            .await
            .map_err(|e| GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            })?
            .get()
            .await
            .map_err(|e| GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            })?;
        let s = String::from_utf8(bytes)
            .map_err(|e| GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            })?;

        Ok(serde_json::from_str(&s)
            .map_err(|e| GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            })?)
    }

    async fn list_indexed<T: StorableType>(
        &self,
        _path: &str,
        _skip: i64,
        _page_size: i64,
        _index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        Err(GoogleCloudStorerError::NotFound {}.into())
    }

    async fn create<T: StorableType>(&self, entry: Entry<T>) -> Result<Entry<T>, CryptoError> {
        let entry_string = serde_json::to_string(&entry)
            .map_err(|e| GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            })?;

        match self.get_client()
            .await?
            .bucket("entries")
            .await
            .map_err(|e| GoogleCloudStorerError::InternalError {
                source: Box::new(e),
            })?
            .create_object(&entry.path, entry_string.as_bytes(), "application/json")
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
