use crate::{
    Builder, ByteSource, CryptoError, HasBuilder, HasIndex, TypeBuilder, TypeBuilderContainer,
    VectorByteSource,
};
use mongodb::bson::{self, Document};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Display, str::FromStr};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t", content = "c")]
pub enum Data {
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    String(String),
}

impl Display for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Data::Bool(b) => b.to_string(),
                Data::U64(n) => n.to_string(),
                Data::I64(n) => n.to_string(),
                Data::F64(n) => n.to_string(),
                Data::String(s) => s.to_owned(),
            }
        )
    }
}

impl From<Data> for ByteSource {
    fn from(d: Data) -> ByteSource {
        ByteSource::Vector(VectorByteSource::new(d.to_string().as_ref()))
    }
}

impl HasIndex for Data {
    type Index = Document;

    fn get_index() -> Option<Self::Index> {
        Some(bson::doc! {
        "c": {
                    "builder": {
            "t": "Data",
            }
        }
            })
    }
}

impl HasBuilder for Data {
    type Builder = DataBuilder;

    fn builder(&self) -> Self::Builder {
        match self {
            Self::Bool(_) => DataBuilder::Bool(BoolDataBuilder {}),
            Self::U64(_) => DataBuilder::U64(U64DataBuilder {}),
            Self::I64(_) => DataBuilder::I64(I64DataBuilder {}),
            Self::F64(_) => DataBuilder::F64(F64DataBuilder {}),
            Self::String(_) => DataBuilder::String(StringDataBuilder {}),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(tag = "t", content = "c")]
pub enum DataBuilder {
    Bool(BoolDataBuilder),
    U64(U64DataBuilder),
    I64(I64DataBuilder),
    F64(F64DataBuilder),
    String(StringDataBuilder),
}

impl TryFrom<TypeBuilderContainer> for DataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(db) => Ok(db),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for DataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        match self {
            Self::Bool(bdb) => bdb.build(bytes),
            Self::U64(ndb) => ndb.build(bytes),
            Self::I64(ndb) => ndb.build(bytes),
            Self::F64(ndb) => ndb.build(bytes),
            Self::String(sdb) => sdb.build(bytes),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct BoolDataBuilder {}

impl TryFrom<TypeBuilderContainer> for BoolDataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::Bool(bdb)) => Ok(bdb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for BoolDataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        let b = bool::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        Ok(Data::Bool(b))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct U64DataBuilder {}

impl TryFrom<TypeBuilderContainer> for U64DataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::U64(ndb)) => Ok(ndb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for U64DataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        let n = u64::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        Ok(Data::U64(n))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct I64DataBuilder {}

impl TryFrom<TypeBuilderContainer> for I64DataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::I64(ndb)) => Ok(ndb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for I64DataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        let n = i64::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        Ok(Data::I64(n))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct F64DataBuilder {}

impl TryFrom<TypeBuilderContainer> for F64DataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::F64(ndb)) => Ok(ndb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for F64DataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        let n = f64::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        Ok(Data::F64(n))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct StringDataBuilder {}

impl TryFrom<TypeBuilderContainer> for StringDataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::String(sdb)) => Ok(sdb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl Builder for StringDataBuilder {
    type Output = Data;

    fn build(&self, bytes: &[u8]) -> Result<Self::Output, CryptoError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
        Ok(Data::String(s))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BoolDataBuilder, Data, DataBuilder, F64DataBuilder, I64DataBuilder, StringDataBuilder,
        U64DataBuilder,
    };
    use crate::{
        key::sodiumoxide::SodiumOxideSymmetricKeyBuilder, Builder, ByteSource, HasBuilder,
        HasIndex, KeyBuilder, SymmetricKeyBuilder, TypeBuilder, TypeBuilderContainer,
    };
    use mongodb::bson::{self, Document};
    use std::convert::{Into, TryInto};

    #[test]
    fn test_display_bool_data() {
        let d_true = Data::Bool(true);
        let d_false = Data::Bool(false);

        assert_eq!(d_true.to_string(), "true");
        assert_eq!(d_false.to_string(), "false");
    }

    #[test]
    fn test_display_u64_data() {
        let d = Data::U64(10);

        assert_eq!(d.to_string(), "10");
    }

    #[test]
    fn test_display_i64_data() {
        let d = Data::I64(-10);

        assert_eq!(d.to_string(), "-10");
    }

    #[test]
    fn test_display_f64_data() {
        let d = Data::F64(10.53);

        assert_eq!(d.to_string(), "10.53");
    }

    #[test]
    fn test_display_string_data() {
        let d = Data::String("hello, world!".to_owned());

        assert_eq!(d.to_string(), "hello, world!");
    }

    #[test]
    fn test_data_to_bytesource() {
        let d = Data::String("hello, world!".to_owned());
        let bs: ByteSource = d.into();

        assert_eq!(
            String::from_utf8(bs.get().unwrap().to_vec()).unwrap(),
            "hello, world!".to_owned()
        );
    }

    #[test]
    fn test_data_to_index() {
        let index: Document = Data::get_index().unwrap();

        assert_eq!(
            index,
            bson::doc! {
            "c": {
                        "builder": {
                "t": "Data",
                        }
            }
                }
        );
    }

    #[test]
    fn test_data_to_builder() {
        let db = Data::Bool(true);
        let du = Data::U64(10);
        let di = Data::I64(-10);
        let df = Data::F64(-10.46);
        let ds = Data::String("hello, world!".to_owned());

        assert_eq!(
            db.builder().build(b"true").unwrap().to_string(),
            db.to_string()
        );
        assert_eq!(
            du.builder().build(b"10").unwrap().to_string(),
            du.to_string()
        );
        assert_eq!(
            di.builder().build(b"-10").unwrap().to_string(),
            di.to_string()
        );
        assert_eq!(
            df.builder().build(b"-10.46").unwrap().to_string(),
            df.to_string()
        );
        assert_eq!(
            ds.builder().build(b"hello, world!").unwrap().to_string(),
            ds.to_string()
        );
    }

    #[test]
    fn test_databuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {})));
        let db: DataBuilder = tbc.try_into().unwrap();
        let d = db.build(b"true").unwrap();
        match d {
            Data::Bool(b) => assert_eq!(b, true),
            _ => panic!("Extracted data should have been a bool-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_databuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Symmetric(
            SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
        )));
        let _: DataBuilder = tbc.try_into().unwrap();
    }

    #[test]
    fn test_booldatabuilder_build_true() {
        let bdb = BoolDataBuilder {};
        let d = bdb.build(b"true").unwrap();
        match d {
            Data::Bool(b) => assert_eq!(b, true),
            _ => panic!("Extracted data should have been a bool-type"),
        }
    }

    #[test]
    fn test_booldatabuilder_build_false() {
        let bdb = BoolDataBuilder {};
        let d = bdb.build(b"false").unwrap();
        match d {
            Data::Bool(b) => assert_eq!(b, false),
            _ => panic!("Extracted data should have been a bool-type"),
        }
    }

    #[test]
    fn test_booldatabuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {})));
        let _: BoolDataBuilder = tbc.try_into().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_booldatabuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Symmetric(
            SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
        )));
        let _: BoolDataBuilder = tbc.try_into().unwrap();
    }

    #[test]
    fn test_u64databuilder_build_valid() {
        let udb = U64DataBuilder {};
        let d = udb.build(b"10").unwrap();
        match d {
            Data::U64(n) => assert_eq!(n, 10),
            _ => panic!("Extracted data should have been a u64-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_u64databuilder_build_invalid() {
        let udb = U64DataBuilder {};
        udb.build(b"-10").unwrap();
    }

    #[test]
    fn test_u64databuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::U64(U64DataBuilder {})));
        let _: U64DataBuilder = tbc.try_into().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_u64databuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Symmetric(
            SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
        )));
        let _: U64DataBuilder = tbc.try_into().unwrap();
    }

    #[test]
    fn test_i64databuilder_build_valid() {
        let udb = I64DataBuilder {};
        let d = udb.build(b"-10").unwrap();
        match d {
            Data::I64(n) => assert_eq!(n, -10),
            _ => panic!("Extracted data should have been a i64-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_i64databuilder_build_invalid() {
        let udb = I64DataBuilder {};
        udb.build(b"-10.54").unwrap();
    }

    #[test]
    fn test_i64databuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::I64(I64DataBuilder {})));
        let _: I64DataBuilder = tbc.try_into().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_i64databuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Symmetric(
            SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
        )));
        let _: I64DataBuilder = tbc.try_into().unwrap();
    }

    #[test]
    fn test_f64databuilder_build_valid() {
        let udb = F64DataBuilder {};
        let d = udb.build(b"-10.53").unwrap();
        match d {
            Data::F64(n) => assert!((n + 10.53).abs() < f64::EPSILON),
            _ => panic!("Extracted data should have been a f64-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_f64databuilder_build_invalid() {
        let udb = F64DataBuilder {};
        udb.build(b"somestr").unwrap();
    }

    #[test]
    fn test_f64databuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::F64(F64DataBuilder {})));
        let _: F64DataBuilder = tbc.try_into().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_f64databuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Symmetric(
            SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
        )));
        let _: F64DataBuilder = tbc.try_into().unwrap();
    }

    #[test]
    fn test_stringdatabuilder_build_valid() {
        let sdb = StringDataBuilder {};
        let d = sdb.build(b"hello, world!").unwrap();
        match d {
            Data::String(s) => assert_eq!(s, "hello, world!".to_owned()),
            _ => panic!("Extracted data should have been a string-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_stringdatabuilder_build_invalid() {
        let udb = StringDataBuilder {};
        udb.build(vec![0xc3, 0x28].as_ref()).unwrap();
    }

    #[test]
    fn test_stringdatabuilder_from_typebuildercontainer_valid() {
        let tbc =
            TypeBuilderContainer(TypeBuilder::Data(DataBuilder::String(StringDataBuilder {})));
        let db: StringDataBuilder = tbc.try_into().unwrap();
        let d = db.build(b"hello, world!").unwrap();
        match d {
            Data::String(s) => assert_eq!(s, "hello, world!".to_owned()),
            _ => panic!("Extracted data should have been a string-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_stringdatabuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Symmetric(
            SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
        )));
        let _: StringDataBuilder = tbc.try_into().unwrap();
    }
}