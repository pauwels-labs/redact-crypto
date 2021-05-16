use crate::keys::{Key, KeyCollection};
use crate::storage::{KeyStorer, StorageError};
use async_trait::async_trait;

#[derive(Clone)]
pub struct RedactKeyStorer {
    url: String,
}

impl RedactKeyStorer {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
        }
    }
}

#[async_trait]
impl KeyStorer for RedactKeyStorer {
    async fn get(&self, name: &str) -> Result<Key, StorageError> {
        match reqwest::get(&format!("{}/keys/{}", self.url, name)).await {
            Ok(r) => Ok(r
                .json::<Key>()
                .await
                .map_err(|source| StorageError::InternalError {
                    source: Box::new(source),
                })?),
            Err(source) => Err(StorageError::InternalError {
                source: Box::new(source),
            }),
        }
    }

    async fn list(&self) -> Result<KeyCollection, StorageError> {
        match reqwest::get(&format!("{}/keys", self.url)).await {
            Ok(r) => Ok(r.json::<KeyCollection>().await.map_err(|source| {
                StorageError::InternalError {
                    source: Box::new(source),
                }
            })?),
            Err(source) => Err(StorageError::InternalError {
                source: Box::new(source),
            }),
        }
    }

    async fn create(&self, value: Key) -> Result<bool, StorageError> {
        let client = reqwest::Client::new();
        match client
            .post(&format!("{}/keys", self.url))
            .json(&value)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(source) => Err(StorageError::InternalError {
                source: Box::new(source),
            }),
        }
    }
}
