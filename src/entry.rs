use crate::{
    ByteSource, ByteUnsealable, CryptoError, Data, DataBuilder, HasByteSource, HasIndex, Key,
    KeyBuilder,
};
use mongodb::bson::Document;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub type EntryPath = String;

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    pub path: EntryPath,
    pub value: State,
}

impl Entry {
    pub fn into_ref(self) -> State {
        State::Referenced {
            builder: match self.value {
                State::Referenced { builder, path: _ } => builder,
                State::Sealed {
                    builder,
                    unsealable: _,
                } => builder,
                State::Unsealed { builder, bytes: _ } => builder,
            },
            path: self.path,
        }
    }
}

impl<T: HasBuilder + HasByteSource> From<T> for State {
    fn from(value: T) -> Self {
        State::Unsealed {
            builder: value.builder().into(),
            bytes: value.byte_source(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "t", content = "c")]
pub enum State {
    Referenced {
        builder: TypeBuilder,
        path: EntryPath,
    },
    Sealed {
        builder: TypeBuilder,
        unsealable: ByteUnsealable,
    },
    Unsealed {
        builder: TypeBuilder,
        bytes: ByteSource,
    },
}

pub trait HasBuilder {
    type Builder: Builder<Output = Self>;

    fn builder(&self) -> Self::Builder;
}

pub trait Builder: TryFrom<TypeBuilderContainer, Error = CryptoError> + Into<TypeBuilder> {
    type Output;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError>;
}

pub trait ToState: HasBuilder + HasByteSource {
    fn to_ref_state(&self, path: EntryPath) -> Result<State, CryptoError> {
        Ok(State::Referenced {
            builder: self.builder().into(),
            path,
        })
    }

    fn to_sealed_state(&self, unsealable: ByteUnsealable) -> Result<State, CryptoError> {
        Ok(State::Sealed {
            builder: self.builder().into(),
            unsealable,
        })
    }

    fn to_unsealed_state(&self, mut bytes: ByteSource) -> Result<State, CryptoError> {
        bytes.set(self.byte_source().get()?)?;
        Ok(State::Unsealed {
            builder: self.builder().into(),
            bytes,
        })
    }
}

impl<T: HasBuilder + HasByteSource> ToState for T {}

/// Need this to provide a level an indirection for TryFrom
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct TypeBuilderContainer(pub TypeBuilder);

//#[derive(Serialize, Deserialize, Debug)]
//#[serde(tag = "t", content = "c")]
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

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
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

    #[test]
    fn test_entry_into_ref() {
        let s = State::Unsealed {
            builder: TypeBuilder::Data(DataBuilder::String(StringDataBuilder {})),
            bytes: "hello, world!".into(),
        };
        let e = Entry {
            path: ".somePath.".to_owned(),
            value: s,
        };
        let s_ref = e.into_ref();
        match s_ref {
            State::Referenced { builder, path } => {
                match builder {
                    TypeBuilder::Data(DataBuilder::String(_)) => (),
                    _ => panic!("Referenced builder should have been a StringDataBuilder"),
                };
                assert_eq!(path, ".somePath.".to_owned());
            }
            _ => panic!("Outputted state should have been a Referenced"),
        }
    }

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
