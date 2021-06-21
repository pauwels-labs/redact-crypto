pub mod error;
pub mod mongodb;
pub mod redact;

use crate::{Buildable, Name, States};
use async_trait::async_trait;
use error::StorageError;
use std::{ops::Deref, sync::Arc};

// #[async_trait]
// pub trait StorerWithType<T>: Send + Sync {
//     /// Fetches the instance of the `Key` with the given name.
//     async fn get(&self, name: &str) -> Result<TypeStates<T>, StorageError>
//     where
//         T: Stateful;

//     /// Fetches a list of all the stored keys.
//     async fn list(&self) -> Result<Vec<TypeStates<T>>, StorageError>
//     where
//         T: Stateful;

//     /// Adds the given `Key` struct to the backing store.
//     async fn create(&self, name: Name, value: T) -> Result<bool, StorageError>
//     where
//         T: Into<TypeStates<Types>> + Send + Sync + Serialize;
// }

/// The operations a storer of `Key` structs must be able to fulfill.
#[async_trait]
pub trait Storer: Clone + Send + Sync {
    /// Fetches the instance of the `Key` with the given name.
    async fn get<T: Buildable>(&self, name: &str) -> Result<T, StorageError>;

    /// Fetches a list of all the stored keys.
    async fn list<T: Buildable + Send>(
        &self,
        name: &Name,
        skip: i64,
        page_size: i64,
    ) -> Result<Vec<T>, StorageError>;

    /// Adds the given `Key` struct to the backing store.
    async fn create(&self, name: Name, value: States) -> Result<bool, StorageError>;

    // fn with_type<T, U>(&self) -> U
    // where
    //     U: StorerWithType<T>;
}

// impl<A: Into<Types>, C: Storer<A>, D: Storer<Box<dyn Into<Types>>>> From<C> for D {
//     fn from(storer: C) -> D {
//         storer as D
//     }
// }

/// Allows an `Arc<KeyStorer>` to act exactly like a `KeyStorer`, dereferencing
/// itself and passing calls through to the underlying `KeyStorer`.
#[async_trait]
impl<U> Storer for Arc<U>
where
    U: Storer,
{
    async fn get<T: Buildable>(&self, name: &str) -> Result<T, StorageError> {
        self.deref().get::<T>(name).await
    }

    async fn list<T: Buildable + Send>(
        &self,
        name: &Name,
        skip: i64,
        page_size: i64,
    ) -> Result<Vec<T>, StorageError> {
        self.deref().list::<T>(name, skip, page_size).await
    }

    async fn create(&self, name: Name, key: States) -> Result<bool, StorageError> {
        self.deref().create(name, key).await
    }

    // fn with_type<T, S>(&self) -> S
    // where
    //     S: StorerWithType<T>,
    // {
    //     self.deref().with_type()
    // }
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
