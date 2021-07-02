use crate::{
    ByteSource, ByteUnsealable, CryptoError, Data, DataBuilder, HasIndex, Key, KeyBuilder,
};
use mongodb::bson::Document;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub type EntryPath = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entry {
    pub path: EntryPath,
    pub value: States,
}

impl Entry {
    pub fn into_ref(self) -> States {
        States::Referenced {
            builder: match self.value {
                States::Referenced { builder, path: _ } => builder,
                States::Sealed {
                    builder,
                    unsealable: _,
                } => builder,
                States::Unsealed { builder, bytes: _ } => builder,
            },
            path: self.path,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum States {
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

pub trait Builder: TryFrom<TypeBuilderContainer, Error = CryptoError> {
    type Output;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError>;
}

/// Need this to provide a level an indirection for TryFrom
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct TypeBuilderContainer(pub TypeBuilder);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
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

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        match self {
            Self::Key(k) => Ok(Type::Key(k.build(bytes)?)),
            Self::Data(d) => Ok(Type::Data(d.build(bytes)?)),
        }
    }
}
