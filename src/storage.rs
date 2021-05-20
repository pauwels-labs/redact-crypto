pub mod error;
pub mod mongodb;
pub mod redact;

pub use self::{error::StorageError, mongodb::MongoKeyStorer, redact::RedactKeyStorer};
use crate::keys::{Key, KeyCollection};
use async_trait::async_trait;

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
