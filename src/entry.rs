use crate::{
    Algorithm, ByteAlgorithm, ByteSource, CryptoError, Data, DataBuilder, HasByteSource, HasIndex,
    Key, KeyBuilder, Storer, TypeStorer,
};
use async_recursion::async_recursion;
use mongodb::bson::Document;
use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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
    DeserializeOwned
    + Serialize
    + HasByteSource
    + HasBuilder
    + HasIndex<Index = Document>
    + Unpin
    + Send
    + std::fmt::Debug
    + 'static
{
}

impl<T: StorableType> Entry<T> {
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

// pub trait ToState: HasBuilder + HasByteSource {
//     fn to_ref_state(&self, path: EntryPath) -> Result<State, CryptoError> {
//         Ok(State::Referenced {
//             builder: self.builder().into(),
//             path,
//         })
//     }

//     fn to_sealed_state(&self, unsealable: ByteAlgorithm) -> Result<State, CryptoError> {
//         Ok(State::Sealed {
//             builder: self.builder().into(),
//             unsealable,
//         })
//     }

//     fn to_unsealed_state(&self, mut bytes: ByteSource) -> Result<State, CryptoError> {
//         bytes.set(self.byte_source().get()?)?;
//         Ok(State::Unsealed {
//             builder: self.builder().into(),
//             bytes,
//         })
//     }
// }

// impl<T: HasBuilder + HasByteSource> ToState for T {}

/// Need this to provide a level an indirection for TryFrom
#[derive(Serialize, Deserialize, Copy, Clone)]
pub struct TypeBuilderContainer(pub TypeBuilder);

pub enum Type {
    Key(Key),
    Data(Data),
}

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
    use super::{Entry, State, Type, TypeBuilder, TypeBuilderContainer};
    use crate::{
        BoolDataBuilder, Builder, Data, DataBuilder, HasBuilder, HasIndex, StringDataBuilder,
    };
    use std::convert::TryInto;

    // #[test]
    // fn test_entry_into_ref() {
    //     let s = State::Unsealed {
    //         builder: TypeBuilder::Data(DataBuilder::String(StringDataBuilder {})),
    //         bytes: "hello, world!".into(),
    //     };
    //     let e = Entry {
    //         path: ".somePath.".to_owned(),
    //         value: s,
    //     };
    //     let s_ref = e.into_ref();
    //     match s_ref {
    //         State::Referenced { builder, path } => {
    //             match builder {
    //                 TypeBuilder::Data(DataBuilder::String(_)) => (),
    //                 _ => panic!("Referenced builder should have been a StringDataBuilder"),
    //             };
    //             assert_eq!(path, ".somePath.".to_owned());
    //         }
    //         _ => panic!("Outputted state should have been a Referenced"),
    //     }
    // }

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
