use crate::{CryptoError, Entry, StorableType, Storer, TypeStorer};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};
use mongodb::bson::Document;
use cloud_storage::Client;
use once_cell::sync::OnceCell;
use cloud_storage::Error::Other;

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
    // project_name: String,
    #[serde(skip)]
    client: Client,
}

impl From<GoogleCloudStorer> for TypeStorer {
    fn from(gcs: GoogleCloudStorer) -> Self {
        TypeStorer::GoogleCloud(gcs)
    }
}

impl GoogleCloudStorer {
    pub fn new() -> Self {
        return GoogleCloudStorer {
            client: Client::new(),
        }
    }
}

//
// impl GoogleCloudStorer {
//     async fn get_client(&self) -> Result<Client, GoogleCloudStorerError> {
//         Client::new(&self.project_name)
//             .await
//             .map_err(|e| GoogleCloudStorerError::InternalError {
//                 source: Box::new(e),
//             })
//     }
// }

#[async_trait]
impl Storer for GoogleCloudStorer {
    async fn get_indexed<T: StorableType>(
        &self,
        path: &str,
        _index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError> {
        let bytes = self.client
            .object()
            .download("default_bucket_hw", path)
            .await
            .map_err(|e| {
                match e {
                    Other(e) => {
                        GoogleCloudStorerError::NotFound {}
                    },
                    _ => {
                        GoogleCloudStorerError::InternalError {
                            source: Box::new(e),
                        }
                    }
                }
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

        match self.client
            .object()
            .create("default_bucket_hw", entry_string.as_bytes().to_vec(), &entry.path.clone(), "application/json")
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
