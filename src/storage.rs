pub mod error;
pub mod mongodb;
pub mod redact;

use crate::{CryptoError, KeyName, Stateful, TypeStates, Types};
use async_trait::async_trait;
use error::StorageError;
use serde::Serialize;
use std::{
    convert::{Into, TryFrom},
    ops::Deref,
    sync::Arc,
};

#[async_trait]
pub trait StorerWithType<T>: Send + Sync {
    /// Fetches the instance of the `Key` with the given name.
    async fn get(&self, name: &str) -> Result<T, StorageError>
    where
        T: TryFrom<TypeStates<Types>, Error = CryptoError> + Stateful;

    /// Fetches a list of all the stored keys.
    async fn list(&self) -> Result<Vec<T>, StorageError>
    where
        T: TryFrom<TypeStates<Types>, Error = CryptoError> + Stateful;

    /// Adds the given `Key` struct to the backing store.
    async fn create(&self, name: KeyName, value: T) -> Result<bool, StorageError>
    where
        T: Into<Types> + Send + Sync + Serialize;
}

/// The operations a storer of `Key` structs must be able to fulfill.
#[async_trait]
pub trait Storer: Clone + Send + Sync {
    /// Fetches the instance of the `Key` with the given name.
    async fn get<T>(&self, name: &str) -> Result<TypeStates<T>, StorageError>
    where
        T: Stateful;

    /// Fetches a list of all the stored keys.
    async fn list<T>(&self) -> Result<Vec<TypeStates<T>>, StorageError>
    where
        T: Stateful;

    /// Adds the given `Key` struct to the backing store.
    async fn create<T>(&self, name: KeyName, value: T) -> Result<bool, StorageError>
    where
        T: Into<TypeStates<Types>> + Send + Sync + Serialize;

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
    async fn get<T>(&self, name: &str) -> Result<TypeStates<T>, StorageError>
    where
        T: Stateful,
    {
        self.deref().get(name).await
    }

    async fn list<T>(&self) -> Result<Vec<TypeStates<T>>, StorageError>
    where
        T: Stateful,
    {
        self.deref().list().await
    }

    async fn create<T>(&self, name: KeyName, key: T) -> Result<bool, StorageError>
    where
        T: Into<TypeStates<Types>> + Send + Sync + Serialize,
    {
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
