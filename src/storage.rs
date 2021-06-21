pub mod error;
pub mod mongodb;
pub mod redact;

use crate::{
    Buildable, Builder, CryptoError, Entry, EntryPath, IntoIndex, States, TypeBuilderContainer,
    Unsealer,
};
use ::mongodb::bson::Document;
use async_trait::async_trait;
use error::StorageError;
use std::{convert::TryFrom, ops::Deref, sync::Arc};

/// The operations a storer of `Key` structs must be able to fulfill.
#[async_trait]
pub trait Storer: Clone + Send + Sync {
    /// Fetches the instance of the `Key` with the given name.
    async fn get<T: IntoIndex + Buildable>(&self, path: &str) -> Result<Entry, StorageError> {
        self.get_indexed::<T>(path, &T::into_index()).await
    }

    /// Like get, but doesn't enforce IntoIndex and allows providing a custom index doc
    async fn get_indexed<T: Buildable>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry, StorageError>;

    /// Fetches a list of all the stored keys.
    async fn list<T: IntoIndex + Buildable + Send>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
    ) -> Result<Vec<Entry>, StorageError> {
        self.list_indexed::<T>(path, skip, page_size, &T::into_index())
            .await
    }

    /// Like list, but doesn't enforce IntoIndex and allows providing a custom index doc
    async fn list_indexed<T: Buildable + Send>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry>, StorageError>;

    /// Adds the given `Key` struct to the backing store.
    async fn create(&self, path: EntryPath, value: States) -> Result<bool, StorageError>;

    /// Takes an entry and resolves it down into its final unsealed type using this storage
    async fn resolve<T: IntoIndex + Buildable>(&self, entry: &Entry) -> Result<T, CryptoError> {
        self.resolve_indexed::<T>(entry, &T::into_index()).await
    }

    /// Takes an entry and resolves it down into its final unsealed type using this storage
    async fn resolve_indexed<T: Buildable>(
        &self,
        entry: &Entry,
        index: &Option<Document>,
    ) -> Result<T, CryptoError> {
        match &entry.value {
            States::Referenced { builder: _, path } => {
                match self.get_indexed::<T>(path, index).await {
                    Ok(output) => Ok(self.resolve_indexed::<T>(&output, index).await?),
                    Err(e) => Err(CryptoError::StorageError { source: e }),
                }
            }
            States::Sealed {
                builder,
                unsealer: unsealable,
            } => {
                let bytes = match unsealable.unseal(self.clone()).await {
                    Ok(v) => Ok(v),
                    Err(e) => Err(e),
                }?;
                let builder =
                    match <T as Buildable>::Builder::try_from(TypeBuilderContainer(*builder)) {
                        Ok(b) => Ok(b),
                        Err(e) => Err(e),
                    }?;
                match builder.build(bytes.as_ref()) {
                    Ok(output) => Ok(output),
                    Err(e) => Err(e),
                }
            }
            States::Unsealed { builder, bytes } => {
                let builder =
                    match <T as Buildable>::Builder::try_from(TypeBuilderContainer(*builder)) {
                        Ok(b) => Ok(b),
                        Err(e) => Err(e),
                    }?;
                match builder.build(bytes.as_ref()) {
                    Ok(output) => Ok(output),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

/// Allows an `Arc<KeyStorer>` to act exactly like a `KeyStorer`, dereferencing
/// itself and passing calls through to the underlying `KeyStorer`.
#[async_trait]
impl<U> Storer for Arc<U>
where
    U: Storer,
{
    async fn get_indexed<T: Buildable>(
        &self,
        name: &str,
        index: &Option<Document>,
    ) -> Result<Entry, StorageError> {
        self.deref().get_indexed::<T>(name, index).await
    }

    async fn list_indexed<T: Buildable + Send>(
        &self,
        name: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry>, StorageError> {
        self.deref()
            .list_indexed::<T>(name, skip, page_size, index)
            .await
    }

    async fn create(&self, name: EntryPath, key: States) -> Result<bool, StorageError> {
        self.deref().create(name, key).await
    }
}

// pub mod tests {
//     use crate::{MaybeSealedSourceCollection, KeyName, KeyStorer, Keys, StorageError};
//     use async_trait::async_trait;
//     use mockall::predicate::*;
//     use mockall::*;
//     use serde::{de::DeserializeOwned, Serialize};
//     use std::fmt::Debug;

//     mock! {
//     pub KeyStorer {}
//     #[async_trait]
//     impl KeyStorer for KeyStorer {
//         async fn get<T>(&self, name: &str) -> Result<T, StorageError>
//         where
//         T: Serialize + Debug + Unpin + DeserializeOwned + Send + Sync + 'static;
//         async fn list(
//         &self,
//         ) -> Result<MaybeSealedSourceCollection, StorageError>;
//         async fn create(&self, name: KeyName, value: Keys) -> Result<bool, StorageError>;
//     }
//     impl Clone for DataStorer {
//         fn clone(&self) -> Self;
//     }
//     }

//     #[test]
//     fn test_unit() {
//         assert!(true);
//     }
// }
