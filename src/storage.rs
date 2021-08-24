//! The storage module covers all aspects of CRUD operations on Redact data-types.
//! It allows for retrieving data entries stored in a Redact database. These data entries
//! can be either unencrypted bytes, encrypted bytes, or a reference pointing to another entry.
//!
//! Read operations allow for retrieval of data based on type information and the data's path.
//!

pub mod mongodb;
pub mod redact;
pub mod google_cloud_storage;

use crate::{CryptoError, Entry, StorableType};
use ::mongodb::bson::Document;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{ops::Deref, sync::Arc};

pub trait HasIndex {
    type Index;

    fn get_index() -> Option<Self::Index>;
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TypeStorer {
    Redact(redact::RedactStorer),
    Mongo(mongodb::MongoStorer),
    GoogleCloud(google_cloud_storage::GoogleCloudStorer),
    Mock(tests::MockStorer),
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
            TypeStorer::GoogleCloud(gcs) => gcs.get_indexed(path, index).await,
            TypeStorer::Mock(ms) => ms.get_indexed(path, index).await,
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
            TypeStorer::GoogleCloud(gcs) => gcs.list_indexed(path, skip, page_size, index).await,
            TypeStorer::Mock(ms) => ms.list_indexed(path, skip, page_size, index).await,
        }
    }

    async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError> {
        match self {
            TypeStorer::Redact(rs) => rs.create(value).await,
            TypeStorer::Mongo(ms) => ms.create(value).await,
            TypeStorer::GoogleCloud(gcs) => gcs.create(value).await,
            TypeStorer::Mock(ms) => ms.create(value).await,
        }
    }
}

/// The operations a storer of `Key` structs must be able to fulfill.
#[async_trait]
pub trait Storer: Send + Sync {
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
    async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError>;
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

    async fn create<T: StorableType>(&self, key: Entry<T>) -> Result<Entry<T>, CryptoError> {
        self.deref().create(key).await
    }
}

pub mod tests {
    use super::Storer as StorerTrait;
    use crate::{CryptoError, Entry, StorableType, TypeStorer};
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;
    use mongodb::bson::Document;
    use serde::{Deserialize, Serialize};

    mock! {
    pub Storer {
        pub fn private_deserialize() -> Self;
        pub fn private_serialize(&self) -> MockStorer;
    pub fn private_get_indexed<T: StorableType>(&self, path: &str, index: &Option<Document>) -> Result<Entry<T>, CryptoError>;
    pub fn private_list_indexed<T: StorableType>(&self, path: &str, skip: i64, page_size: i64, index: &Option<Document>) -> Result<Vec<Entry<T>>, CryptoError>;
    pub fn private_create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError>;
    }
    }

    impl core::fmt::Debug for MockStorer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockStorer").finish()
        }
    }

    #[async_trait]
    impl StorerTrait for MockStorer {
        async fn get_indexed<T: StorableType>(
            &self,
            path: &str,
            index: &Option<Document>,
        ) -> Result<Entry<T>, CryptoError> {
            self.private_get_indexed(path, index)
        }
        async fn list_indexed<T: StorableType>(
            &self,
            path: &str,
            skip: i64,
            page_size: i64,
            index: &Option<Document>,
        ) -> Result<Vec<Entry<T>>, CryptoError> {
            self.private_list_indexed(path, skip, page_size, index)
        }
        async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError> {
            self.private_create(value)
        }
    }

    impl Serialize for MockStorer {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.private_serialize().serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for MockStorer {
        fn deserialize<D>(_: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(MockStorer::private_deserialize())
        }
    }

    impl From<MockStorer> for TypeStorer {
        fn from(ms: MockStorer) -> Self {
            TypeStorer::Mock(ms)
        }
    }
}
