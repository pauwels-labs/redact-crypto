//! The storage module covers all aspects of CRUD operations on Redact data-types.
//! It allows for retrieving data entries stored in a Redact database. These data entries
//! can be either unencrypted bytes, encrypted bytes, or a reference pointing to another entry.
//!
//! Read operations allow for retrieval of data based on type information and the data's path.
//!

pub mod error;
pub mod mongodb;
pub mod redact;

use crate::{Builder, Entry, EntryPath, HasBuilder, States, TypeBuilderContainer, Unsealable};
use ::mongodb::bson::Document;
use async_trait::async_trait;
use error::StorageError;
use std::convert::TryFrom;

pub trait HasIndex {
    type Index;

    fn get_index() -> Option<Self::Index>;
}

/// The operations a storer of `Key` structs must be able to fulfill.
#[async_trait]
pub trait Storer: Clone + Send + Sync {
    /// Fetches the instance of the `Key` with the given name.
    async fn get<T: HasIndex<Index = Document> + HasBuilder + 'static>(
        &self,
        path: &str,
    ) -> Result<Entry, StorageError> {
        self.get_indexed::<T>(path, &T::get_index()).await
    }

    /// Like get, but doesn't enforce IntoIndex and allows providing a custom index doc
    async fn get_indexed<T: HasBuilder + 'static>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry, StorageError>;

    /// Fetches a list of all the stored keys.
    async fn list<T: HasIndex<Index = Document> + HasBuilder + Send + 'static>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
    ) -> Result<Vec<Entry>, StorageError> {
        self.list_indexed::<T>(path, skip, page_size, &T::get_index())
            .await
    }

    /// Like list, but doesn't enforce IntoIndex and allows providing a custom index doc
    async fn list_indexed<T: HasBuilder + Send + 'static>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry>, StorageError>;

    /// Adds the given `Key` struct to the backing store.
    async fn create(&self, path: EntryPath, value: States) -> Result<bool, StorageError>;

    /// Takes an entry and resolves it down into its final unsealed type using this storage
    async fn resolve<T: HasIndex<Index = Document> + HasBuilder + 'static>(
        &self,
        state: States,
    ) -> Result<T, StorageError> {
        self.resolve_indexed::<T>(state, &T::get_index()).await
    }

    /// Takes an entry and resolves it down into its final unsealed type using this storage
    async fn resolve_indexed<T: HasBuilder + 'static>(
        &self,
        state: States,
        index: &Option<Document>,
    ) -> Result<T, StorageError> {
        match state {
            States::Referenced {
                builder: _,
                ref path,
            } => match self.get_indexed::<T>(path, index).await {
                Ok(output) => Ok(self.resolve_indexed::<T>(output.value, index).await?),
                Err(e) => Err(e),
            },
            States::Sealed {
                builder,
                unsealable,
            } => {
                let bytes = match unsealable.unseal(self.clone()).await {
                    Ok(v) => Ok(v),
                    Err(e) => Err(StorageError::InternalError {
                        source: Box::new(e),
                    }),
                }?;
                let builder =
                    match <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(builder)) {
                        Ok(b) => Ok(b),
                        Err(e) => Err(StorageError::InternalError {
                            source: Box::new(e),
                        }),
                    }?;
                match builder.build(bytes.get_source().get().map_err(|e| {
                    StorageError::InternalError {
                        source: Box::new(e),
                    }
                })?) {
                    Ok(output) => Ok(output),
                    Err(e) => Err(StorageError::InternalError {
                        source: Box::new(e),
                    }),
                }
            }
            States::Unsealed { builder, bytes } => {
                let builder =
                    match <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(builder)) {
                        Ok(b) => Ok(b),
                        Err(e) => Err(StorageError::InternalError {
                            source: Box::new(e),
                        }),
                    }?;
                let bytes = bytes.get().map_err(|e| StorageError::InternalError {
                    source: Box::new(e),
                })?;
                match builder.build(bytes) {
                    Ok(output) => Ok(output),
                    Err(e) => Err(StorageError::InternalError {
                        source: Box::new(e),
                    }),
                }
            }
        }
    }
}

/// Allows an `Arc<KeyStorer>` to act exactly like a `KeyStorer`, dereferencing
/// itself and passing calls through to the underlying `KeyStorer`.
// #[async_trait]
// impl<U> Storer for Arc<U>
// where
//     U: Storer,
// {
//     async fn get_indexed<T: HasBuilder>(
//         &self,
//         name: &str,
//         index: &Option<Document>,
//     ) -> Result<Entry, StorageError> {
//         self.deref().get_indexed::<T>(name, index).await
//     }

//     async fn list_indexed<T: HasBuilder + Send>(
//         &self,
//         name: &str,
//         skip: i64,
//         page_size: i64,
//         index: &Option<Document>,
//     ) -> Result<Vec<Entry>, StorageError> {
//         self.deref()
//             .list_indexed::<T>(name, skip, page_size, index)
//             .await
//     }

//     async fn create(&self, name: EntryPath, key: States) -> Result<bool, StorageError> {
//         self.deref().create(name, key).await
//     }
// }

pub mod tests {
    use super::Storer;
    use crate::{Entry, EntryPath, HasBuilder, States, StorageError};
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;
    use mongodb::bson::Document;

    mock! {
    pub Storer {}
    #[async_trait]
    impl Storer for Storer {
    async fn get_indexed<T: HasBuilder + 'static>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry, StorageError>;
    /// Like list, but doesn't enforce IntoIndex and allows providing a custom index doc
    async fn list_indexed<T: HasBuilder + Send + 'static>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry>, StorageError>;
    async fn create(&self, path: EntryPath, value: States) -> Result<bool, StorageError>;
    }
    impl Clone for Storer {
        fn clone(&self) -> Self;
    }
    }
}
