pub mod error;
pub mod mongodb;
pub mod redact;

pub use self::mongodb::MongoKeyStorer;
use crate::keys::{Key, KeyCollection};
use async_trait::async_trait;
pub use error::StorageError;

#[async_trait]
pub trait KeyStorer: Clone + Send + Sync {
    async fn get(&self, name: &str) -> Result<Key, StorageError>;
    async fn list(&self) -> Result<KeyCollection, StorageError>;
    async fn create(&self, value: Key) -> Result<bool, StorageError>;
}
