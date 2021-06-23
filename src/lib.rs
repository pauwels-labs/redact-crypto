//! # redact-crypto
//!
//! The `redact-crypto` crate contains all of the interfaces, data structures,
//! and abstractions necessary to work with cryptographic primitives.
//!
//! Namely, it uses a high-level`Key` struct which contains a KeySource and a `KeyExecutor`.
//! A `KeyExecutor` represents a chunk of logic which is capable of ingesting a `KeySource` and
//! plaintext or ciphertext and perform cryptographic operations on it. A `KeySource` contains
//! the data and logic to interact with a secret key, whether symmetric or asymmetric.
//!
//! Currently, the only `KeySource` supported is a `Bytes`-type source. These are sources that
//! can be deserialized into a raw byte array, and that byte array then used for encryption/
//! decryption/signing operations. In the future, other, non-`Byte` key sources will be
//! implemented to, for example, support the use of hardware key sources where the actual value
//! of the key cannot be retrieved.
//!
//! It also contains implementations of the storage interface for storing and
//! retrieving redact keys with a variety of sources.
//!
//! File directory: [ OUTDATED ]
//! - lib.rs: exports root-level public types from otherwise private submodules
//! - keys.rs: all the structs and traits for representing symmetric and asymmetric keys
//! - error.rs: custom errors that can arise from various key and key field operations
//! - key_sources.rs: all the structs for representing various types of key sourceso
//! - storage.rs: trait for a data type that stores `Key`
//! - storage/error.rs: error types for the storage abstractions
//! - storage/mongodb.rs: storage implentation for mongodb
//! - storage/redact.rs: storage implementation for a redact-store server

mod error;
pub mod keys;
pub mod nonces;
mod sources;
mod storage;
mod typebuilders;
mod types;

pub use error::CryptoError;
pub use nonces::{AsymmetricNonces, Nonces, SymmetricNonces};
pub use sources::{BytesSources, FsBytesSource, Sources, VectorBytesSource};
pub use storage::{error::StorageError, mongodb::MongoStorer, redact::RedactStorer, Storer};
pub use typebuilders::{
    AsymmetricKeyBuilder, DataBuilder, KeyBuilder, PublicAsymmetricKeyBuilder,
    SecretAsymmetricKeyBuilder, SymmetricKeyBuilder, TypeBuilder, TypeBuilderContainer,
};
pub use types::{
    AsymmetricKey, Buildable, Builder, ByteSealable, ByteUnsealable, Data, Entry, EntryPath,
    IntoIndex, Key, PublicAsymmetricKey, Sealable, SymmetricSealer, SecretAsymmetricKey, States,
    SymmetricKey, Type, Unsealable,
};
