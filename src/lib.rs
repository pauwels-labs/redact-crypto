//! # redact-crypto
//!
//! The `redact-crypto` crate contains all of the interfaces, data structures,
//! and abstractions necessary to work with cryptographic primitives and Redact data-types.
//!
//! The motivation behind this crate is to provide a unified interface for interacting with serialized
//! data that may be encrypted. Serializable data types are represented as an enum tree, with the base
//! types being:
//! - bool
//! - u64
//! - i64
//! - f64
//! - Vec<u8>
//! These should cover most use cases for now. In the case of serializing a custom data type,
//! that type can be serialized into bytes and then those bytes turned into a Vec<u8> to
//! be stored in the redact type system.
//!
//! The other set of types in the tree covers cryptographic keys, which are themselves
//! split into symmetric and asymmetric enums. Current keys are exclusively implemented via
//! libsodium, but other implementations will be added based on need.
//!
//! This crate also provides a storage interface for CRUD operations on these data types. The
//! provided implementation can transparently perform these operations on unencrypted data,
//! encrypted data, or references to data. This means it can, for example, search for all
//! data of type `AsymmetricKey` and return all possible keys regardless of if that key
//! is encrypted. It also provides resolution functionality that accepts an encrypted piece of
//! data and decrypts it into its final type by fetching the appropriate key from storage. It can
//! do this recursively to resolve an entire chain of encryption.
//!
//! The final interface provided by this crate covers sources. Currently, the only supported source
//! is a byte source, meaning it represents some device which returns a vector of bytes. Current supported
//! bytes sources are memory and filesystem. These can be used interchangeably when a bytes source is
//! required and they will correctly resolve the set of bytes if possible.
//!
//! File directory:
//! - lib.rs: exports root-level public types from otherwise private submodules
//! - error.rs: custom errors that can arise from various redact-crypto operations
//! - sources.rs: types, traits, and implementations for sources of data
//! - typebuilders.rs: types that build types
//! - types.rs: all redact types that can be serialized and stored as unencrypted/
//!             encrypted/referenced
//! - keys.rs: exports key submodules such as sodiumoxide key implementations
//! - keys/sodiumoxide.rs: key implementations backed by sodiumoxide
//! - nonces.rs: nonce hierarchy for each implemented key type
//! - nonces/sodiumoxide.rs: sodiumoxide nonce implementations
//! - storage.rs: trait for a data type that stores `Entry` types
//! - storage/mongodb.rs: storage implentation for mongodb
//! - storage/redact.rs: storage implementation for a redact-store server

mod algorithm;
mod data;
mod entry;
mod error;
pub mod key;
pub mod nonce;
mod source;
pub mod storage;
pub mod x509;

pub use algorithm::{Algorithm, ByteAlgorithm};
pub use data::{
    BoolDataBuilder, Data, DataBuilder, F64DataBuilder, I64DataBuilder, StringDataBuilder,
    U64DataBuilder, BinaryDataBuilder, BinaryData, BinaryType
};
pub use entry::{
    Builder, Entry, EntryPath, HasBuilder, State, StorableType, ToEntry, Type, TypeBuilder,
    TypeBuilderContainer,
};
pub use error::CryptoError;
pub use key::{
    AsymmetricKey, AsymmetricKeyBuilder, HasAlgorithmIdentifier, HasPublicKey, Key, KeyBuilder,
    PublicAsymmetricKey, PublicAsymmetricKeyBuilder, PublicAsymmetricSealer,
    PublicAsymmetricUnsealer, SecretAsymmetricKey, SecretAsymmetricKeyBuilder,
    SecretAsymmetricSealer, SecretAsymmetricUnsealer, Signer, SymmetricKey, SymmetricKeyBuilder,
    SymmetricSealer, SymmetricUnsealer, ToPublicAsymmetricByteAlgorithm,
    ToSecretAsymmetricByteAlgorithm, ToSymmetricByteAlgorithm, Verifier,
};
pub use nonce::{AsymmetricNonce, Nonce, SymmetricNonce};
pub use source::{
    ByteSource, FsByteSource, HasByteSource, Path, Source, SourceError, VectorByteSource,
};
pub use storage::{
    mongodb::{MongoStorer, MongoStorerError},
    redact::{RedactStorer, RedactStorerError},
    HasIndex, Storer, TypeStorer,
};
