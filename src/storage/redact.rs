use crate::{Buildable, Entry, EntryPath, States, StorageError, Storer};
use async_trait::async_trait;
use mongodb::bson::Document;

#[derive(Clone)]
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

#[async_trait]
impl Storer for RedactStorer {
    async fn get_indexed<T: Buildable>(
        &self,
        path: &str,
        index: &Document,
    ) -> Result<Entry, StorageError> {
        match reqwest::get(&format!("{}/{}?index={}", &self.url, path, index)).await {
            Ok(r) => Ok(r
                .json::<Entry>()
                .await
                .map_err(|source| StorageError::InternalError {
                    source: Box::new(source),
                })?),
            Err(source) => Err(StorageError::InternalError {
                source: Box::new(source),
            }),
        }
    }

    async fn list_indexed<T: Buildable + Send>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Document,
    ) -> Result<Vec<Entry>, StorageError> {
        match reqwest::get(&format!(
            "{}/{}?index={}&skip={}&skip={}",
            &self.url, path, index, skip, page_size
        ))
        .await
        {
            Ok(r) => {
                Ok(r.json::<Vec<Entry>>()
                    .await
                    .map_err(|source| StorageError::InternalError {
                        source: Box::new(source),
                    })?)
            }
            Err(source) => Err(StorageError::InternalError {
                source: Box::new(source),
            }),
        }
    }

    async fn create(&self, path: EntryPath, value: States) -> Result<bool, StorageError> {
        let entry = Entry { path, value };
        let client = reqwest::Client::new();
        match client
            .post(&format!("{}/", self.url))
            .json(&entry)
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
