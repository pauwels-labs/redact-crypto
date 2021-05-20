pub mod error;
pub mod mongodb;
pub mod redact;

use crate::keys::{Key, KeyCollection};
use async_trait::async_trait;
use error::StorageError;

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
