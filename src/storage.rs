//! The storage module covers all aspects of CRUD operations on Redact data-types.
//! It allows for retrieving data entries stored in a Redact database. These data entries
//! can be either unencrypted bytes, encrypted bytes, or a reference pointing to another entry.
//!
//! Read operations allow for retrieval of data based on type information and the data's path.
//!

pub mod mongodb;
pub mod redact;

use crate::{CryptoError, Entry, StorableType};
use ::mongodb::bson::Document;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{ops::Deref, sync::Arc};

pub trait HasIndex {
    type Index;

    fn get_index() -> Option<Self::Index>;
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum TypeStorer {
    Redact(redact::RedactStorer),
    Mongo(mongodb::MongoStorer),
}

#[async_trait]
impl Storer for TypeStorer {
    async fn get_indexed<T: StorableType>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError> {
        match self {
            TypeStorer::Redact(rs) => rs.get_indexed(path, index).await,
            TypeStorer::Mongo(ms) => ms.get_indexed(path, index).await,
        }
    }

    async fn list_indexed<T: StorableType>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        match self {
            TypeStorer::Redact(rs) => rs.list_indexed(path, skip, page_size, index).await,
            TypeStorer::Mongo(ms) => ms.list_indexed(path, skip, page_size, index).await,
        }
    }

    async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<bool, CryptoError> {
        match self {
            TypeStorer::Redact(rs) => rs.create(value).await,
            TypeStorer::Mongo(ms) => ms.create(value).await,
        }
    }
}

/// The operations a storer of `Key` structs must be able to fulfill.
#[async_trait]
pub trait Storer: Clone + Send + Sync {
    /// Fetches the instance of the `Key` with the given name.
    async fn get<T: HasIndex<Index = Document> + StorableType>(
        &self,
        path: &str,
    ) -> Result<Entry<T>, CryptoError> {
        self.get_indexed::<T>(path, &T::get_index()).await
    }

    /// Like get, but doesn't enforce IntoIndex and allows providing a custom index doc
    async fn get_indexed<T: StorableType>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError>;

    /// Fetches a list of all the stored keys.
    async fn list<T: HasIndex<Index = Document> + StorableType>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        self.list_indexed::<T>(path, skip, page_size, &T::get_index())
            .await
    }

    /// Like list, but doesn't enforce IntoIndex and allows providing a custom index doc
    async fn list_indexed<T: StorableType>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError>;

    /// Adds the given `Key` struct to the backing store.
    async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<bool, CryptoError>;

    // /// Takes an entry and resolves it down into its final unsealed type using this storage
    // async fn resolve<T: HasIndex<Index = Document> + HasByteSource + HasBuilder + 'static>(
    //     &self,
    //     entry: &Entry<T>,
    // ) -> Result<&T, CryptoError> {
    //     self.resolve_indexed::<T>(entry, &T::get_index()).await
    // }

    // /// Takes an entry and resolves it down into its final unsealed type using this storage
    // async fn resolve_indexed<T: HasByteSource + HasBuilder + 'static>(
    //     &self,
    //     entry: &Entry<T>,
    //     index: &Option<Document>,
    // ) -> Result<&T, CryptoError> {
    //     match entry.value {
    //         State::Referenced { ref path } => match self.get_indexed::<T>(path, index).await {
    //             Ok(output) => Ok(self.resolve_indexed::<T>(&output, index).await?),
    //             Err(e) => Err(e),
    //         },
    //         State::Sealed {
    //             ref ciphertext,
    //             ref algorithm,
    //         } => {
    //             let plaintext = algorithm.unseal(ciphertext, self).await?;
    //             let builder =
    //                 <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(entry.builder))?;
    //             builder.build(Some(plaintext.get()?))
    //         }
    //         State::Unsealed { ref bytes } => {
    //             let builder =
    //                 <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(entry.builder))?;
    //             builder.build(Some(bytes.get()?))
    //         }
    //     }
    // }
}

// Allows an `Arc<Storer>` to act exactly like a `Storer`, dereferencing
// itself and passing calls through to the underlying `Storer`.
#[async_trait]
impl<U> Storer for Arc<U>
where
    U: Storer,
{
    async fn get_indexed<T: StorableType>(
        &self,
        name: &str,
        index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError> {
        self.deref().get_indexed::<T>(name, index).await
    }

    async fn list_indexed<T: StorableType>(
        &self,
        name: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        self.deref()
            .list_indexed::<T>(name, skip, page_size, index)
            .await
    }

    async fn create<T: StorableType>(&self, key: Entry<T>) -> Result<bool, CryptoError> {
        self.deref().create(key).await
    }
}

#[cfg(test)]
pub mod tests {
    use super::Storer;
    use crate::{CryptoError, Entry, HasBuilder, HasByteSource};
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;
    use mongodb::bson::Document;

    mock! {
    pub Storer {}
    #[async_trait]
    impl Storer for Storer {
    async fn get_indexed<T: HasByteSource + HasBuilder + 'static>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError>;
    async fn list_indexed<T: HasByteSource + HasBuilder + Send + 'static>(
        &self,
        path: &str,
        skip: i64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError>;
    async fn create<T: HasByteSource + HasBuilder + 'static>(&self, value: Entry<T>) -> Result<bool, CryptoError>;
    }
    impl Clone for Storer {
        fn clone(&self) -> Self;
    }
    }
}
