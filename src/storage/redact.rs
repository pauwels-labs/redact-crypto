use crate::{Entry, EntryPath, HasBuilder, States, StorageError, Storer};
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
    async fn get_indexed<T: HasBuilder>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry, StorageError> {
        let mut req_url = format!("{}/{}?", &self.url, path);
        if let Some(i) = index {
            req_url.push_str(format!("index={}", i).as_ref());
        }
        match reqwest::get(&req_url).await {
            Ok(r) => Ok(r
                .error_for_status()
                .map_err(|source| {
                    if source.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                        StorageError::NotFound
                    } else {
                        StorageError::InternalError {
                            source: Box::new(source),
                        }
                    }
                })?
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

    async fn list_indexed<T: HasBuilder + Send>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry>, StorageError> {
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
                .map_err(|source| {
                    if source.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                        StorageError::NotFound
                    } else {
                        StorageError::InternalError {
                            source: Box::new(source),
                        }
                    }
                })?
                .json::<Vec<Entry>>()
                .await
                .map_err(|source| StorageError::InternalError {
                    source: Box::new(source),
                })?),
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
