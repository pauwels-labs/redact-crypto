use crate::{
    Algorithm, ByteAlgorithm, ByteSource, CryptoError, Data, DataBuilder, HasByteSource, HasIndex,
    Key, KeyBuilder, Storer, ToPublicAsymmetricByteAlgorithm, ToSecretAsymmetricByteAlgorithm,
    ToSymmetricByteAlgorithm, TypeStorer,
};
use async_recursion::async_recursion;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mongodb::bson::Document;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub type EntryPath = String;

#[derive(Serialize, Deserialize, Debug)]
#[serde(bound = "T: StorableType")]
pub struct Entry<T> {
    pub path: EntryPath,
    pub builder: TypeBuilder,
    pub value: State,
    #[serde(skip)]
    resolved_value: OnceCell<T>,
}

pub trait StorableType:
    HasByteSource + HasBuilder + HasIndex<Index = Document> + Unpin + Send + std::fmt::Debug + 'static
{
}

impl<T: ToSymmetricByteAlgorithm + StorableType> Entry<T> {
    pub async fn to_symmetric_byte_algorithm(
        self,
        nonce: Option<<T as ToSymmetricByteAlgorithm>::Nonce>,
    ) -> Result<ByteAlgorithm, CryptoError> {
        let (key, entry_path, state) = self.take_resolve_all().await?;
        key.to_byte_algorithm(nonce, |key| async move {
            match state {
                State::Referenced { path, storer } => key.to_ref_entry(path, storer),
                State::Sealed { algorithm, .. } => key.to_sealed_entry(entry_path, algorithm).await,
                State::Unsealed { .. } => key.to_unsealed_entry(entry_path),
            }
        })
        .await
    }
}

impl<T: ToSecretAsymmetricByteAlgorithm + StorableType> Entry<T> {
    pub async fn to_secret_asymmetric_byte_algorithm(
        self,
        public_key: Option<Entry<<T as ToSecretAsymmetricByteAlgorithm>::PublicKey>>,
        nonce: Option<<T as ToSecretAsymmetricByteAlgorithm>::Nonce>,
    ) -> Result<ByteAlgorithm, CryptoError> {
        let (secret_key, entry_path, state) = self.take_resolve_all().await?;
        secret_key
            .to_byte_algorithm(public_key, nonce, |key| async move {
                match state {
                    State::Referenced { path, storer } => key.to_ref_entry(path, storer),
                    State::Sealed { algorithm, .. } => {
                        key.to_sealed_entry(entry_path, algorithm).await
                    }
                    State::Unsealed { .. } => key.to_unsealed_entry(entry_path),
                }
            })
            .await
    }
}

impl<T: ToPublicAsymmetricByteAlgorithm + StorableType> Entry<T> {
    pub async fn to_public_asymmetric_byte_algorithm(
        self,
        secret_key: Entry<<T as ToPublicAsymmetricByteAlgorithm>::SecretKey>,
        nonce: Option<<T as ToPublicAsymmetricByteAlgorithm>::Nonce>,
    ) -> Result<ByteAlgorithm, CryptoError> {
        let (public_key, entry_path, state) = self.take_resolve_all().await?;
        public_key
            .to_byte_algorithm(secret_key, nonce, |key| async move {
                match state {
                    State::Referenced { path, storer } => key.to_ref_entry(path, storer),
                    State::Sealed { algorithm, .. } => {
                        key.to_sealed_entry(entry_path, algorithm).await
                    }
                    State::Unsealed { .. } => key.to_unsealed_entry(entry_path),
                }
            })
            .await
    }
}

impl<T: StorableType> Entry<T> {
    pub fn cast<U: StorableType>(self) -> Result<Entry<U>, CryptoError> {
        let builder =
            <U as HasBuilder>::Builder::try_from(TypeBuilderContainer(self.builder))?.into();
        Ok(Entry::new(self.path, builder, self.value))
    }

    pub fn new(path: EntryPath, builder: TypeBuilder, value: State) -> Self {
        Entry {
            path,
            builder,
            value,
            resolved_value: OnceCell::new(),
        }
    }

    #[async_recursion]
    pub async fn dereference(self) -> Result<Entry<T>, CryptoError> {
        match self.value {
            State::Referenced {
                ref path,
                ref storer,
            } => {
                let entry = storer.get::<T>(path).await?;
                Ok(entry.dereference().await?)
            }
            _ => Ok(self),
        }
    }

    #[async_recursion]
    pub async fn take_resolve(mut self) -> Result<T, CryptoError> {
        match self.resolved_value.take() {
            None => match self.value {
                State::Referenced {
                    ref path,
                    ref storer,
                } => {
                    let entry = storer.get::<T>(path).await?;
                    Ok(entry.take_resolve().await?)
                }
                State::Sealed {
                    ref ciphertext,
                    ref algorithm,
                } => {
                    let builder =
                        <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(self.builder))?;
                    let plaintext = algorithm.unseal(ciphertext).await?;
                    builder.build(Some(plaintext.get()?))
                }
                State::Unsealed { bytes, .. } => {
                    let builder =
                        <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(self.builder))?;
                    builder.build(Some(bytes.get()?))
                }
            },
            Some(value) => Ok(value),
        }
    }

    #[async_recursion]
    pub async fn take_resolve_all(mut self) -> Result<(T, EntryPath, State), CryptoError> {
        match self.resolved_value.take() {
            None => match self.value {
                State::Referenced {
                    ref path,
                    ref storer,
                } => {
                    let entry = storer.get::<T>(path).await?;
                    entry.take_resolve_all().await
                }
                State::Sealed {
                    ref ciphertext,
                    ref algorithm,
                } => {
                    let builder =
                        <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(self.builder))?;
                    let plaintext = algorithm.unseal(ciphertext).await?;
                    Ok((
                        builder.build(Some(plaintext.get()?))?,
                        self.path,
                        self.value,
                    ))
                }
                State::Unsealed { ref bytes, .. } => {
                    let builder =
                        <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(self.builder))?;
                    Ok((builder.build(Some(bytes.get()?))?, self.path, self.value))
                }
            },
            Some(value) => Ok((value, self.path, self.value)),
        }
    }

    //#[async_recursion]
    pub async fn get_last_modified(&self) -> Result<DateTime<Utc>, CryptoError> {
        match self.value {
            State::Referenced {
                ref path,
                ref storer,
            } => {
                let entry = storer.get::<T>(path).await?;
                entry.get_last_modified().await
            }
            State::Sealed { ref ciphertext, .. } => {
                ciphertext.get_last_modified().map_err(|e| e.into())
            }
            State::Unsealed { ref bytes, .. } => bytes.get_last_modified().map_err(|e| e.into()),
        }
    }

    pub async fn resolve(&self) -> Result<&T, CryptoError> {
        match self.resolved_value.get() {
            None => match self.value {
                State::Referenced {
                    ref path,
                    ref storer,
                } => {
                    let entry = storer.get::<T>(path).await?;
                    let value = entry.take_resolve().await?;
                    Ok(self.resolved_value.get_or_init(|| value))
                }
                State::Sealed {
                    ref ciphertext,
                    ref algorithm,
                } => {
                    let builder =
                        <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(self.builder))?;
                    let plaintext = algorithm.unseal(ciphertext).await?;
                    self.resolved_value
                        .get_or_try_init(|| builder.build(Some(plaintext.get()?)))
                }
                State::Unsealed { ref bytes, .. } => {
                    let builder =
                        <T as HasBuilder>::Builder::try_from(TypeBuilderContainer(self.builder))?;
                    self.resolved_value
                        .get_or_try_init(|| builder.build(Some(bytes.get()?)))
                }
            },
            Some(value) => Ok(value),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", content = "c")]
pub enum State {
    Referenced {
        path: EntryPath,
        storer: TypeStorer,
    },
    Sealed {
        ciphertext: ByteSource,
        algorithm: ByteAlgorithm,
    },
    Unsealed {
        bytes: ByteSource,
    },
}

pub trait HasBuilder {
    type Builder: Builder<Output = Self>;

    fn builder(&self) -> Self::Builder;
}

pub trait Builder:
    TryFrom<TypeBuilderContainer, Error = CryptoError> + Into<TypeBuilder> + Send
{
    type Output;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError>;
}

#[async_trait]
pub trait ToEntry: StorableType + Sized {
    fn to_ref_entry<S: Storer + Into<TypeStorer>>(
        self,
        path: EntryPath,
        storer: S,
    ) -> Result<Entry<Self>, CryptoError> {
        Ok(Entry::new(
            path.clone(),
            self.builder().into(),
            State::Referenced {
                storer: storer.into(),
                path,
            },
        ))
    }

    async fn to_sealed_entry(
        self,
        path: EntryPath,
        algorithm: ByteAlgorithm,
    ) -> Result<Entry<Self>, CryptoError> {
        let byte_source = self.byte_source();
        let ciphertext = algorithm.seal(&byte_source).await?;
        Ok(Entry::new(
            path,
            self.builder().into(),
            State::Sealed {
                ciphertext,
                algorithm,
            },
        ))
    }

    fn to_unsealed_entry(self, path: EntryPath) -> Result<Entry<Self>, CryptoError> {
        Ok(Entry::new(
            path,
            self.builder().into(),
            State::Unsealed {
                bytes: self.byte_source(),
            },
        ))
    }
}

impl<T: StorableType> ToEntry for T {}

/// Need this to provide a level an indirection for TryFrom
#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct TypeBuilderContainer(pub TypeBuilder);

#[derive(Debug)]
pub enum Type {
    Key(Key),
    Data(Data),
}

impl StorableType for Type {}

impl HasIndex for Type {
    type Index = Document;

    fn get_index() -> Option<Self::Index> {
        None
    }
}

impl HasBuilder for Type {
    type Builder = TypeBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::Key(kb) => TypeBuilder::Key(kb.builder()),
            Self::Data(db) => TypeBuilder::Data(db.builder()),
        }
    }
}

impl HasByteSource for Type {
    fn byte_source(&self) -> ByteSource {
        match self {
            Self::Key(kb) => kb.byte_source(),
            Self::Data(db) => db.byte_source(),
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
#[serde(tag = "t", content = "c")]
pub enum TypeBuilder {
    Data(DataBuilder),
    Key(KeyBuilder),
}

impl TryFrom<TypeBuilderContainer> for TypeBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        Ok(builder.0)
    }
}

impl Builder for TypeBuilder {
    type Output = Type;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match self {
            Self::Key(k) => Ok(Type::Key(k.build(bytes)?)),
            Self::Data(d) => Ok(Type::Data(d.build(bytes)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Type, TypeBuilder, TypeBuilderContainer};
    use crate::{
        BoolDataBuilder, Builder, Data, DataBuilder, HasBuilder, HasIndex, StringDataBuilder,
    };
    use std::convert::TryInto;

    #[test]
    fn test_type_to_index() {
        assert_eq!(Type::get_index(), None);
    }

    #[test]
    fn test_type_to_builder() {
        let t = Type::Data(Data::String("hello, world!".to_owned()));
        let tb = t.builder();
        match tb {
            TypeBuilder::Data(DataBuilder::String(_)) => (),
            _ => panic!("Outputted builder should have been a StringDataBuilder"),
        }
    }

    #[test]
    fn test_typebuilder_build_valid() {
        let tb = TypeBuilder::Data(DataBuilder::String(StringDataBuilder {}));
        let t = tb.build(Some(b"hello, world!")).unwrap();
        match t {
            Type::Data(Data::String(s)) => assert_eq!(s, "hello, world!".to_owned()),
            _ => panic!("Extracted type should have been a data string-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_typebuilder_build_invalid() {
        let tb = TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {}));
        tb.build(Some(b"not a bool")).unwrap();
    }

    #[test]
    fn test_typebuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {})));
        let tb: TypeBuilder = tbc.try_into().unwrap();
        let t = tb.build(Some(b"true")).unwrap();
        match t {
            Type::Data(Data::Bool(b)) => assert_eq!(b, true),
            _ => panic!("Extracted data should have been a bool-type"),
        }
    }
}
