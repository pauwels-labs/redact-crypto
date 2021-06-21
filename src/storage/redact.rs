use crate::{Buildable, Builder, EntryPath, States, StorageError, Storer, Unsealer};
use async_trait::async_trait;
use std::convert::TryFrom;

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
    async fn get<T: Buildable>(&self, name: &str) -> Result<T, StorageError> {
        match reqwest::get(&format!("{}/keys/{}", &self.url, name)).await {
            Ok(r) => {
                let value =
                    r.json::<States>()
                        .await
                        .map_err(|source| StorageError::InternalError {
                            source: Box::new(source),
                        })?;
                match value {
                    States::Referenced { path: name } => Ok(self.get::<T>(&name).await?),
                    States::Sealed {
                        builder,
                        unsealer: unsealable,
                    } => {
                        let bytes = unsealable
                            .unseal(self.clone())
                            .await
                            .map_err(|_| StorageError::NotFound)?;
                        let builder = <T as Buildable>::Builder::try_from(builder)
                            .map_err(|_| StorageError::NotFound)?;
                        let output = builder
                            .build(bytes.as_ref())
                            .map_err(|_| StorageError::NotFound)?;
                        Ok(output)
                    }
                    States::Unsealed { builder, bytes } => {
                        let builder = <T as Buildable>::Builder::try_from(builder)
                            .map_err(|_| StorageError::NotFound)?;
                        let output = builder
                            .build(bytes.as_ref())
                            .map_err(|_| StorageError::NotFound)?;
                        Ok(output)
                    }
                }
            }
            Err(source) => Err(StorageError::InternalError {
                source: Box::new(source),
            }),
        }
    }

    async fn list<T: Buildable + Send>(
        &self,
        name: &EntryPath,
        skip: i64,
        page_size: i64,
    ) -> Result<Vec<T>, StorageError> {
        Ok(vec![])
        // match reqwest::get(&format!("{}/keys", self.url)).await {
        //     Ok(r) => {
        //         let entry_collection = r.json::<Vec<Entry<Types>>>().await.map_err(|source| {
        //             StorageError::InternalError {
        //                 source: Box::new(source),
        //             }
        //         })?;
        //         Ok(entry_collection
        //             .iter()
        //             .filter_map(|entry| {
        //                 let ts = entry.value.clone();
        //                 match ts {
        //                     TypeStates::Reference(rt) => T::ReferenceType::try_from(rt)
        //                         .map_or_else(|_| None, |value| Some(TypeStates::Reference(value))),
        //                     TypeStates::Sealed(st) => T::SealedType::try_from(st)
        //                         .map_or_else(|_| None, |value| Some(TypeStates::Sealed(value))),
        //                     TypeStates::Unsealed(t) => T::UnsealedType::try_from(t)
        //                         .map_or_else(|_| None, |value| Some(TypeStates::Unsealed(value))),
        //                 }
        //             })
        //             .collect())
        //     }
        //     Err(source) => Err(StorageError::InternalError {
        //         source: Box::new(source),
        //     }),
        // }
    }

    async fn create(&self, name: EntryPath, key: States) -> Result<bool, StorageError> {
        Ok(true)
        // let entry = Entry {
        //     name,
        //     value: key.into(),
        // };
        // let client = reqwest::Client::new();
        // match client
        //     .post(&format!("{}/keys", self.url))
        //     .json(&entry)
        //     .send()
        //     .await
        // {
        //     Ok(_) => Ok(true),
        //     Err(source) => Err(StorageError::InternalError {
        //         source: Box::new(source),
        //     }),
        // }
    }
}
