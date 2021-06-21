use crate::{Buildable, Entry, EntryPath, IntoIndex, States, StorageError, Storer};
use async_trait::async_trait;

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
    async fn get<T: IntoIndex + Buildable>(&self, path: &str) -> Result<Entry, StorageError> {
        match reqwest::get(&format!("{}/{}?index={}", &self.url, path, T::into_index(),)).await {
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

    async fn list<T: IntoIndex + Buildable + Send>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
    ) -> Result<Vec<Entry>, StorageError> {
        match reqwest::get(&format!(
            "{}/{}?index={}&skip={}&skip={}",
            &self.url,
            path,
            T::into_index(),
            skip,
            page_size
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
