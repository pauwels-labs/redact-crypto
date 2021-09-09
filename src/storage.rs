//! The storage module covers all aspects of CRUD operations on Redact data-types.
//! It allows for retrieving data entries stored in a Redact database. These data entries
//! can be either unencrypted bytes, encrypted bytes, or a reference pointing to another entry.
//!
//! Read operations allow for retrieval of data based on type information and the data's path.
//!

pub mod mongodb;
pub mod redact;
pub mod gcs;

use crate::{CryptoError, Entry, StorableType};
use ::mongodb::bson::Document;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub trait HasIndex {
    type Index;

    fn get_index() -> Option<Self::Index>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TypeStorer {
    IndexedTypeStorer(IndexedTypeStorer),
    NonIndexedTypeStorer(NonIndexedTypeStorer)
}

#[async_trait]
impl Storer for TypeStorer {
    async fn get<T: StorableType>(&self, path: &str) -> Result<Entry<T>, CryptoError> {
        match self {
            TypeStorer::NonIndexedTypeStorer(ts) => ts.get(path).await,
            TypeStorer::IndexedTypeStorer(ts) => ts.get(path).await
        }
    }

    async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError> {
        match self {
            TypeStorer::NonIndexedTypeStorer(ts) => ts.create(value).await,
            TypeStorer::IndexedTypeStorer(ts) => ts.create(value).await
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum IndexedTypeStorer {
    Redact(redact::RedactStorer),
    Mongo(mongodb::MongoStorer),
    Mock(tests::MockIndexedStorer),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NonIndexedTypeStorer {
    GoogleCloud(gcs::GoogleCloudStorer),
    Mock(tests::MockStorer),
}

#[async_trait]
impl IndexedStorer for IndexedTypeStorer {
    async fn get_indexed<T: StorableType>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError> {
        match self {
            IndexedTypeStorer::Redact(rs) => rs.get_indexed(path, index).await,
            IndexedTypeStorer::Mongo(ms) => ms.get_indexed(path, index).await,
            IndexedTypeStorer::Mock(ms) => ms.get_indexed(path, index).await,
        }
    }

    async fn list<T: StorableType>(
        &self,
        path: &str,
        skip: u64,
        page_size: i64,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        match self {
            IndexedTypeStorer::Redact(rs) => rs.list(path, skip, page_size).await,
            IndexedTypeStorer::Mongo(ms) => ms.list(path, skip, page_size).await,
            IndexedTypeStorer::Mock(ms) => ms.list(path, skip, page_size).await,
        }
    }

    async fn list_indexed<T: StorableType>(
        &self,
        path: &str,
        skip: u64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        match self {
            IndexedTypeStorer::Redact(rs) => rs.list_indexed(path, skip, page_size, index).await,
            IndexedTypeStorer::Mongo(ms) => ms.list_indexed(path, skip, page_size, index).await,
            IndexedTypeStorer::Mock(ms) => ms.list_indexed(path, skip, page_size, index).await,
        }
    }
}

#[async_trait]
impl Storer for IndexedTypeStorer {
    async fn get<T: StorableType>(
        &self,
        path: &str,
    ) -> Result<Entry<T>, CryptoError> {
        match self {
            IndexedTypeStorer::Redact(rs) => rs.get(path).await,
            IndexedTypeStorer::Mongo(ms) => ms.get(path).await,
            IndexedTypeStorer::Mock(ms) => ms.get(path).await,
        }
    }

    async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError> {
        match self {
            IndexedTypeStorer::Redact(rs) => rs.create(value).await,
            IndexedTypeStorer::Mongo(ms) => ms.create(value).await,
            IndexedTypeStorer::Mock(ms) => ms.create(value).await,
        }
    }
}

#[async_trait]
impl Storer for NonIndexedTypeStorer {
    async fn get<T: StorableType>(
        &self,
        path: &str,
    ) -> Result<Entry<T>, CryptoError> {
        match self {
            NonIndexedTypeStorer::GoogleCloud(gcs) => gcs.get(path).await,
            NonIndexedTypeStorer::Mock(ms) => ms.get(path).await,
        }
    }

    async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError> {
        match self {
            NonIndexedTypeStorer::GoogleCloud(gcs) => gcs.create(value).await,
            NonIndexedTypeStorer::Mock(ms) => ms.create(value).await,
        }
    }
}

/// The operations a storer of `Key` structs must be able to fulfill.
#[async_trait]
pub trait IndexedStorer: Send + Sync + Storer {

    /// Like get, but doesn't enforce IntoIndex and allows providing a custom index doc
    async fn get_indexed<T: StorableType>(
        &self,
        path: &str,
        index: &Option<Document>,
    ) -> Result<Entry<T>, CryptoError>;

    /// Fetches a list of all the stored keys.
    async fn list<T: StorableType>(
        &self,
        path: &str,
        skip: u64,
        page_size: i64,
    ) -> Result<Vec<Entry<T>>, CryptoError> {
        self.list_indexed::<T>(path, skip, page_size, &T::get_index())
            .await
    }

    /// Like list, but doesn't enforce IntoIndex and allows providing a custom index doc
    async fn list_indexed<T: StorableType>(
        &self,
        path: &str,
        skip: u64,
        page_size: i64,
        index: &Option<Document>,
    ) -> Result<Vec<Entry<T>>, CryptoError>;
}

/// The operations a storer of `Key` structs must be able to fulfill.
#[async_trait]
pub trait Storer: Send + Sync {
    /// Fetches the instance of the `Key` with the given name.
    async fn get<T: StorableType>(
        &self,
        path: &str,
    ) -> Result<Entry<T>, CryptoError>;

    /// Adds the given `Key` struct to the backing store.
    async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError>;
}

pub mod tests {
    use super::Storer as StorerTrait;
    use super::IndexedStorer as IndexedStorerTrait;
    use crate::{CryptoError, Entry, StorableType, TypeStorer, IndexedTypeStorer};
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;
    use mongodb::bson::Document;
    use serde::{Deserialize, Serialize};
    use crate::storage::NonIndexedTypeStorer;

    mock! {
    pub IndexedStorer {
        pub fn private_deserialize() -> Self;
        pub fn private_serialize(&self) -> MockIndexedStorer;
    pub fn private_get_indexed<T: StorableType>(&self, path: &str, index: &Option<Document>) -> Result<Entry<T>, CryptoError>;
    pub fn private_list_indexed<T: StorableType>(&self, path: &str, skip: u64, page_size: i64, index: &Option<Document>) -> Result<Vec<Entry<T>>, CryptoError>;
    pub fn private_get<T: StorableType>(&self, path: &str) -> Result<Entry<T>, CryptoError>;
    pub fn private_list<T: StorableType>(&self, path: &str, skip: u64, page_size: i64) -> Result<Vec<Entry<T>>, CryptoError>;
    pub fn private_create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError>;
    }
    }

    mock! {
    pub Storer {
        pub fn private_deserialize() -> Self;
        pub fn private_serialize(&self) -> MockIndexedStorer;
    pub fn private_get<T: StorableType>(&self, path: &str) -> Result<Entry<T>, CryptoError>;
    pub fn private_create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError>;
    }
    }

    impl core::fmt::Debug for MockIndexedStorer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockStorer").finish()
        }
    }

    impl Clone for MockIndexedStorer {
        fn clone(&self) -> Self {
            unimplemented!()
        }
    }

    impl core::fmt::Debug for MockStorer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockIndexedStorer").finish()
        }
    }

    impl Clone for MockStorer {
        fn clone(&self) -> Self {
            unimplemented!()
        }
    }

    #[async_trait]
    impl IndexedStorerTrait for MockIndexedStorer {
        async fn get_indexed<T: StorableType>(
            &self,
            path: &str,
            index: &Option<Document>,
        ) -> Result<Entry<T>, CryptoError> {
            self.private_get_indexed(path, index)
        }
        async fn list<T: StorableType>(
            &self,
            path: &str,
            skip: u64,
            page_size: i64,
        ) -> Result<Vec<Entry<T>>, CryptoError> {
            self.private_list(path, skip, page_size)
        }
        async fn list_indexed<T: StorableType>(
            &self,
            path: &str,
            skip: u64,
            page_size: i64,
            index: &Option<Document>,
        ) -> Result<Vec<Entry<T>>, CryptoError> {
            self.private_list_indexed(path, skip, page_size, index)
        }
    }

        #[async_trait]
    impl StorerTrait for MockIndexedStorer {
        async fn get<T: StorableType>(
            &self,
            path: &str,
        ) -> Result<Entry<T>, CryptoError> {
            self.private_get(path)
        }
        async fn create<T: StorableType>(&self, value: Entry<T>) -> Result<Entry<T>, CryptoError> {
            self.private_create(value)
        }
    }

    #[async_trait]
    impl StorerTrait for MockStorer {
        async fn get<T: StorableType>(
            &self,
            path: &str,
        ) -> Result<Entry<T>, CryptoError> {
            self.private_get(path)
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

    impl Serialize for MockIndexedStorer {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
        {
            self.private_serialize().serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for MockIndexedStorer {
        fn deserialize<D>(_: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
        {
            Ok(MockIndexedStorer::private_deserialize())
        }
    }

    impl From<MockStorer> for NonIndexedTypeStorer {
        fn from(mis: MockStorer) -> Self {
            NonIndexedTypeStorer::Mock(mis)
        }
    }

    impl From<MockIndexedStorer> for IndexedTypeStorer {
        fn from(mis: MockIndexedStorer) -> Self {
            IndexedTypeStorer::Mock(mis)
        }
    }

    impl From<MockIndexedStorer> for TypeStorer {
        fn from(mis: MockIndexedStorer) -> Self {
            TypeStorer::IndexedTypeStorer(IndexedTypeStorer::Mock(mis))
        }
    }

    impl From<MockStorer> for TypeStorer {
        fn from(mis: MockStorer) -> Self {
            TypeStorer::NonIndexedTypeStorer(NonIndexedTypeStorer::Mock(mis))
        }
    }
}
