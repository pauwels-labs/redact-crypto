pub mod error;
pub mod mongodb;
pub mod redact;

use crate::keys::{Key, KeyCollection};
use async_trait::async_trait;
use error::StorageError;
use std::{ops::Deref, sync::Arc};

/// The operations a storer of `Key` structs must be able to fulfill.
#[async_trait]
pub trait KeyStorer: Clone + Send + Sync {
    /// Fetches the instance of the `Key` with the given name.
    async fn get(&self, name: &str) -> Result<Key, StorageError>;
    /// Fetches a list of all the stored keys.
    async fn list(&self) -> Result<KeyCollection, StorageError>;
    /// Adds the given `Key` struct to the backing store.
    async fn create(&self, value: Key) -> Result<bool, StorageError>;
}

/// Allows an `Arc<KeyStorer>` to act exactly like a `KeyStorer`, dereferencing
/// itself and passing calls through to the underlying `KeyStorer`.
#[async_trait]
impl<U> KeyStorer for Arc<U>
where
    U: KeyStorer,
{
    async fn get(&self, path: &str) -> Result<Key, StorageError> {
        self.deref().get(path).await
    }

    async fn list(&self) -> Result<KeyCollection, StorageError> {
        self.deref().list().await
    }

    async fn create(&self, value: Key) -> Result<bool, StorageError> {
        self.deref().create(value).await
    }
}

pub mod tests {
    use crate::{Key, KeyCollection, KeyStorer, StorageError};
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::*;

    mock! {
    pub KeyStorer {}
    #[async_trait]
    impl KeyStorer for KeyStorer {
        async fn get(&self, path: &str) -> Result<Key, StorageError>;
        async fn list(
        &self,
        ) -> Result<KeyCollection, StorageError>;
        async fn create(&self, value: Key) -> Result<bool, StorageError>;
    }
    impl Clone for DataStorer {
        fn clone(&self) -> Self;
    }
    }

    #[test]
    fn test_unit() {
        assert!(true);
    }
}
