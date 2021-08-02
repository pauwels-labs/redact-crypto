//! The storage module covers all aspects of CRUD operations on Redact data-types.
//! It allows for retrieving data entries stored in a Redact database. These data entries
//! can be either unencrypted bytes, encrypted bytes, or a reference pointing to another entry.
//!
//! Read operations allow for retrieval of data based on type information and the data's path.
//!

pub mod mongodb;
pub mod redact;

use crate::{
    Algorithm, Builder, CryptoError, Entry, EntryPath, HasBuilder, State, TypeBuilderContainer,
};
use ::mongodb::bson::Document;
use async_trait::async_trait;
use std::{convert::TryFrom, ops::Deref, sync::Arc};

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
    ) -> Result<Entry, CryptoError> {
        self.get_indexed::<T>(path, &T::get_index()).await
    }

    /// Like get, but doesn't enforce IntoIndex and allows providing a custom index doc
    async fn get_indexed<T: HasBuilder + 'static>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry, CryptoError>;

    /// Fetches a list of all the stored keys.
    async fn list<T: HasIndex<Index = Document> + HasBuilder + Send + 'static>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
    ) -> Result<Vec<Entry>, CryptoError> {
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
    ) -> Result<Vec<Entry>, CryptoError>;

    /// Adds the given `Key` struct to the backing store.
    async fn create(&self, path: EntryPath, value: State) -> Result<bool, CryptoError>;

    /// Takes an entry and resolves it down into its final unsealed type using this storage
    async fn resolve<T: HasIndex<Index = Document> + HasBuilder + 'static>(
        &self,
        entry: &Entry,
    ) -> Result<&T, CryptoError> {
        self.resolve_indexed::<T>(entry, &T::get_index()).await
    }

    /// Takes an entry and resolves it down into its final unsealed type using this storage
    async fn resolve_indexed<T: HasBuilder + 'static>(
        &self,
        entry: &Entry,
        index: &Option<Document>,
    ) -> Result<&T, CryptoError> {
        match entry.value {
            State::Referenced { ref path } => match self.get_indexed::<T>(path, index).await {
                Ok(output) => Ok(self.resolve_indexed::<T>(&output, index).await?),
                Err(e) => Err(e),
            },
            State::Sealed {
                ref ciphertext,
                ref algorithm,
            } => {
                let plaintext = algorithm.unseal(ciphertext, self).await?;
                let builder =
                    <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(entry.builder))?;
                builder.build(Some(plaintext.get()?))
            }
            State::Unsealed { ref bytes } => {
                let builder =
                    <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(entry.builder))?;
                builder.build(Some(bytes.get()?))
            }
        }
    }
}

// Allows an `Arc<Storer>` to act exactly like a `Storer`, dereferencing
// itself and passing calls through to the underlying `Storer`.
#[async_trait]
impl<U> Storer for Arc<U>
where
    U: Storer,
{
    async fn get_indexed<T: HasBuilder + 'static>(
        &self,
        name: &str,
        index: &Option<Document>,
    ) -> Result<Entry, CryptoError> {
        self.deref().get_indexed::<T>(name, index).await
    }

    async fn list_indexed<T: HasBuilder + Send + 'static>(
        &self,
        name: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry>, CryptoError> {
        self.deref()
            .list_indexed::<T>(name, skip, page_size, index)
            .await
    }

    async fn create(&self, name: EntryPath, key: State) -> Result<bool, CryptoError> {
        self.deref().create(name, key).await
    }
}

#[cfg(test)]
pub mod tests {
    use super::Storer;
    use crate::{CryptoError, Entry, EntryPath, HasBuilder, State};
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
    ) -> Result<Entry, CryptoError>;
    async fn list_indexed<T: HasBuilder + Send + 'static>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry>, CryptoError>;
    async fn create(&self, path: EntryPath, value: State) -> Result<bool, CryptoError>;
    }
    impl Clone for Storer {
        fn clone(&self) -> Self;
    }
    }
}
