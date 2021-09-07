use crate::{CryptoError, Entry, StorableType, Storer, IndexedStorer, IndexedTypeStorer};
use async_trait::async_trait;
use mongodb::bson::Document;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

#[derive(Debug)]
pub enum RedactStorerError {
    /// Represents an error which occurred in some internal system
    InternalError {
        source: Box<dyn Error + Send + Sync>,
    },

    /// Requested document was not found
    NotFound,
}

impl Error for RedactStorerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            RedactStorerError::InternalError { ref source } => Some(source.as_ref()),
            RedactStorerError::NotFound => None,
        }
    }
}

impl Display for RedactStorerError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            RedactStorerError::InternalError { .. } => {
                write!(f, "Internal error occurred")
            }
            RedactStorerError::NotFound => {
                write!(f, "Requested document not found")
            }
        }
    }
}

impl From<RedactStorerError> for CryptoError {
    fn from(rse: RedactStorerError) -> Self {
        match rse {
            RedactStorerError::InternalError { .. } => CryptoError::InternalError {
                source: Box::new(rse),
            },
            RedactStorerError::NotFound => CryptoError::NotFound {
                source: Box::new(rse),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RedactStorer {
    url: String,
}

/// Stores an instance of a redact-backed key storer.
/// The redact-store server is an example implementation of a redact storage backing.
impl RedactStorer {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
        }
    }
}

impl From<RedactStorer> for IndexedTypeStorer {
    fn from(rs: RedactStorer) -> Self {
        IndexedTypeStorer::Redact(rs)
    }
}

#[async_trait]
impl IndexedStorer for RedactStorer {
    async fn get_indexed<T: StorableType>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError> {
        let mut req_url = format!("{}/{}?", &self.url, path);
        if let Some(i) = index {
            req_url.push_str(format!("index={}", i).as_ref());
        }
        match reqwest::get(&req_url).await {
            Ok(r) => Ok(r
                .error_for_status()
                .map_err(|source| -> CryptoError {
                    if source.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                        RedactStorerError::NotFound.into()
                    } else {
                        RedactStorerError::InternalError {
                            source: Box::new(source),
                        }
                            .into()
                    }
                })?
                .json::<Entry<T>>()
                .await
                .map_err(|source| -> CryptoError {
                    RedactStorerError::InternalError {
                        source: Box::new(source),
                    }
                        .into()
                })?),
            Err(source) => Err(RedactStorerError::InternalError {
                source: Box::new(source),
            }
                .into()),
        }
    }

    async fn list_indexed<T: StorableType>(
        &self,
        path: &str,
        skip: u64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        let mut req_url = format!(
            "{}/{}?skip={}&page_size={}",
            &self.url, path, skip, page_size
        );
        if let Some(i) = index {
            req_url.push_str(format!("&index={}", i).as_ref());
        }
        match reqwest::get(&req_url).await {
            Ok(r) => Ok(r
                .error_for_status()
                .map_err(|source| -> CryptoError {
                    if source.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                        RedactStorerError::NotFound.into()
                    } else {
                        RedactStorerError::InternalError {
                            source: Box::new(source),
                        }
                            .into()
                    }
                })?
                .json::<Vec<Entry<T>>>()
                .await
                .map_err(|source| -> CryptoError {
                    RedactStorerError::InternalError {
                        source: Box::new(source),
                    }
                        .into()
                })?),
            Err(source) => Err(RedactStorerError::InternalError {
                source: Box::new(source),
            }
                .into()),
        }
    }
}

#[async_trait]
impl Storer for RedactStorer {
    async fn get<T: StorableType>(
        &self,
        path: &str,
    ) -> Result<Entry<T>, CryptoError> {
        self.get_indexed::<T>(path, &T::get_index()).await
    }

    async fn list<T: StorableType>(
        &self,
        path: &str,
        skip: u64,
        page_size: i64,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        self.list_indexed::<T>(path, skip, page_size, &T::get_index())
            .await
    }

    async fn create<T: StorableType>(&self, entry: Entry<T>) -> Result<Entry<T>, CryptoError> {
        let client = reqwest::Client::new();
        let value = serde_json::to_value(&entry).map_err(|e| RedactStorerError::InternalError {
            source: Box::new(e),
        })?;
        client
            .post(&format!("{}/", self.url))
            .json(&value)
            .send()
            .await
            .and_then(|res| res.error_for_status().map(|_| entry))
            .map_err(|e| {
                if let Some(status) = e.status() {
                    if status == StatusCode::NOT_FOUND {
                        RedactStorerError::NotFound.into()
                    } else {
                        RedactStorerError::InternalError {
                            source: Box::new(e),
                        }
                        .into()
                    }
                } else {
                    RedactStorerError::InternalError {
                        source: Box::new(e),
                    }
                    .into()
                }
            })
    }
}
