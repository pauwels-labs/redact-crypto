use crate::{
    Builder, ByteSource, CryptoError, HasBuilder, HasByteSource, HasIndex, StorableType,
    TypeBuilder, TypeBuilderContainer,
};
use mongodb::bson::{self, Document};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Display, str::FromStr};
use strum::EnumIter;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, EnumIter)]
pub enum BinaryType {
    ImageJPEG,
    ImagePNG,
    ImageGIF,
    ImageAPNG,
    ImageAVIF,
    ImageSVG,
    ImageWEBP,
    VideoMP4,
    VideoMPEG,
    Unknown,
}

impl TryFrom<&str> for BinaryType {
    type Error = CryptoError;

    fn try_from(s: &str) -> Result<BinaryType, CryptoError> {
        match s {
            "image/jpeg" => Ok(BinaryType::ImageJPEG),
            "image/png" => Ok(BinaryType::ImagePNG),
            "image/gif" => Ok(BinaryType::ImageGIF),
            "image/apng" => Ok(BinaryType::ImageAPNG),
            "image/avif" => Ok(BinaryType::ImageAVIF),
            "image/svg+xml" => Ok(BinaryType::ImageSVG),
            "image/webp" => Ok(BinaryType::ImageWEBP),
            "video/mp4" => Ok(BinaryType::VideoMP4),
            "video/mpeg" => Ok(BinaryType::VideoMPEG),
            _ => Ok(BinaryType::Unknown),
        }
    }
}

impl Display for BinaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                BinaryType::ImageJPEG => "image/jpeg",
                BinaryType::ImagePNG => "image/png",
                BinaryType::ImageGIF => "image/gif",
                BinaryType::ImageAPNG => "image/apng",
                BinaryType::ImageAVIF => "image/avif",
                BinaryType::ImageSVG => "image/svg+xml",
                BinaryType::ImageWEBP => "image/webp",
                BinaryType::VideoMP4 => "video/mp4",
                BinaryType::VideoMPEG => "video/mpeg",
                BinaryType::Unknown => "unknown",
            }
        )
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BinaryData {
    pub binary: String,
    pub binary_type: BinaryType,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Data {
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    String(String),
    Binary(Option<BinaryData>),
}

impl StorableType for Data {}

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
                Data::Binary(b) => {
                    if let Some(b) = b {
                        serde_json::to_string(b).map_err(|_| std::fmt::Error)?
                    } else {
                        "".to_owned()
                    }
                }
            }
        )
    }
}

impl From<Data> for ByteSource {
    fn from(d: Data) -> ByteSource {
        d.to_string().as_str().into()
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
            Self::Binary(_) => DataBuilder::Binary(BinaryDataBuilder {}),
        }
    }
}

impl HasByteSource for Data {
    fn byte_source(&self) -> ByteSource {
        self.clone().into()
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
    Binary(BinaryDataBuilder),
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

impl From<DataBuilder> for TypeBuilder {
    fn from(db: DataBuilder) -> TypeBuilder {
        TypeBuilder::Data(db)
    }
}

impl Builder for DataBuilder {
    type Output = Data;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match self {
            Self::Bool(bdb) => bdb.build(bytes),
            Self::U64(ndb) => ndb.build(bytes),
            Self::I64(ndb) => ndb.build(bytes),
            Self::F64(ndb) => ndb.build(bytes),
            Self::String(sdb) => sdb.build(bytes),
            Self::Binary(bdb) => bdb.build(bytes),
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

impl From<BoolDataBuilder> for TypeBuilder {
    fn from(bdb: BoolDataBuilder) -> TypeBuilder {
        TypeBuilder::Data(DataBuilder::Bool(bdb))
    }
}

impl Builder for BoolDataBuilder {
    type Output = Data;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => {
                let s = String::from_utf8(bytes.to_vec())
                    .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                let b =
                    bool::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                Ok(Data::Bool(b))
            }
            None => Ok(Data::Bool(false)),
        }
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

impl From<U64DataBuilder> for TypeBuilder {
    fn from(ndb: U64DataBuilder) -> TypeBuilder {
        TypeBuilder::Data(DataBuilder::U64(ndb))
    }
}

impl Builder for U64DataBuilder {
    type Output = Data;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => {
                let s = String::from_utf8(bytes.to_vec())
                    .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                let n =
                    u64::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                Ok(Data::U64(n))
            }
            None => Ok(Data::U64(0)),
        }
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

impl From<I64DataBuilder> for TypeBuilder {
    fn from(ndb: I64DataBuilder) -> TypeBuilder {
        TypeBuilder::Data(DataBuilder::I64(ndb))
    }
}

impl Builder for I64DataBuilder {
    type Output = Data;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => {
                let s = String::from_utf8(bytes.to_vec())
                    .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                let n =
                    i64::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                Ok(Data::I64(n))
            }
            None => Ok(Data::I64(0)),
        }
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

impl From<F64DataBuilder> for TypeBuilder {
    fn from(ndb: F64DataBuilder) -> TypeBuilder {
        TypeBuilder::Data(DataBuilder::F64(ndb))
    }
}

impl Builder for F64DataBuilder {
    type Output = Data;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => {
                let s = String::from_utf8(bytes.to_vec())
                    .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                let n =
                    f64::from_str(&s).map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                Ok(Data::F64(n))
            }
            None => Ok(Data::F64(0.0)),
        }
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

impl From<StringDataBuilder> for TypeBuilder {
    fn from(sdb: StringDataBuilder) -> TypeBuilder {
        TypeBuilder::Data(DataBuilder::String(sdb))
    }
}

impl Builder for StringDataBuilder {
    type Output = Data;

    fn build(&self, bytes: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match bytes {
            Some(bytes) => {
                let s = String::from_utf8(bytes.to_vec())
                    .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                Ok(Data::String(s))
            }
            None => Ok(Data::String("".to_owned())),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct BinaryDataBuilder {}

impl TryFrom<TypeBuilderContainer> for BinaryDataBuilder {
    type Error = CryptoError;

    fn try_from(builder: TypeBuilderContainer) -> Result<Self, Self::Error> {
        match builder.0 {
            TypeBuilder::Data(DataBuilder::Binary(bdb)) => Ok(bdb),
            _ => Err(CryptoError::NotDowncastable),
        }
    }
}

impl From<BinaryDataBuilder> for TypeBuilder {
    fn from(bdb: BinaryDataBuilder) -> TypeBuilder {
        TypeBuilder::Data(DataBuilder::Binary(bdb))
    }
}

impl Builder for BinaryDataBuilder {
    type Output = Data;

    fn build(&self, data: Option<&[u8]>) -> Result<Self::Output, CryptoError> {
        match data {
            Some(binary_data_bytes) => {
                let s = String::from_utf8(binary_data_bytes.to_vec())
                    .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                let bd: BinaryData = serde_json::from_str(&s)
                    .map_err(|_| CryptoError::NotDeserializableToBaseDataType)?;
                Ok(Data::Binary(Some(bd)))
            }
            None => Ok(Data::String("".to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BinaryDataBuilder, BoolDataBuilder, Data, DataBuilder, F64DataBuilder, I64DataBuilder,
        StringDataBuilder, U64DataBuilder,
    };
    use crate::{
        key::sodiumoxide::SodiumOxideSymmetricKeyBuilder, BinaryData, BinaryType, Builder,
        ByteSource, HasBuilder, HasIndex, KeyBuilder, SymmetricKeyBuilder, TypeBuilder,
        TypeBuilderContainer,
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
    fn test_display_binary_jpeg_data() {
        let binary_data = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageJPEG,
        };
        let d = Data::Binary(Some(binary_data));
        assert_eq!(
            d.to_string(),
            "{\"binary\":\"abc\",\"binary_type\":\"ImageJPEG\"}"
        );
    }

    #[test]
    fn test_display_binary_png_data() {
        let binary_data = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImagePNG,
        };
        let d = Data::Binary(Some(binary_data));
        assert_eq!(
            d.to_string(),
            "{\"binary\":\"abc\",\"binary_type\":\"ImagePNG\"}"
        );
    }

    #[test]
    fn test_display_binary_gif_data() {
        let binary_data = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageGIF,
        };
        let d = Data::Binary(Some(binary_data));
        assert_eq!(
            d.to_string(),
            "{\"binary\":\"abc\",\"binary_type\":\"ImageGIF\"}"
        );
    }

    #[test]
    fn test_display_binary_apng_data() {
        let binary_data = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageAPNG,
        };
        let d = Data::Binary(Some(binary_data));
        assert_eq!(
            d.to_string(),
            "{\"binary\":\"abc\",\"binary_type\":\"ImageAPNG\"}"
        );
    }

    #[test]
    fn test_display_binary_avif_data() {
        let binary_data = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageAVIF,
        };
        let d = Data::Binary(Some(binary_data));
        assert_eq!(
            d.to_string(),
            "{\"binary\":\"abc\",\"binary_type\":\"ImageAVIF\"}"
        );
    }

    #[test]
    fn test_display_binary_svg_data() {
        let binary_data = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageSVG,
        };
        let d = Data::Binary(Some(binary_data));
        assert_eq!(
            d.to_string(),
            "{\"binary\":\"abc\",\"binary_type\":\"ImageSVG\"}"
        );
    }

    #[test]
    fn test_display_binary_webp_data() {
        let binary_data = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageWEBP,
        };
        let d = Data::Binary(Some(binary_data));
        assert_eq!(
            d.to_string(),
            "{\"binary\":\"abc\",\"binary_type\":\"ImageWEBP\"}"
        );
    }

    #[test]
    fn test_display_binary_mp4_data() {
        let binary_data = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::VideoMP4,
        };
        let d = Data::Binary(Some(binary_data));
        assert_eq!(
            d.to_string(),
            "{\"binary\":\"abc\",\"binary_type\":\"VideoMP4\"}"
        );
    }

    #[test]
    fn test_display_binary_mpeg_data() {
        let binary_data = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::VideoMPEG,
        };
        let d = Data::Binary(Some(binary_data));
        assert_eq!(
            d.to_string(),
            "{\"binary\":\"abc\",\"binary_type\":\"VideoMPEG\"}"
        );
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

        let binary_jpeg = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageJPEG,
        };
        let d_binary_jpeg = Data::Binary(Some(binary_jpeg));

        let binary_png = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImagePNG,
        };
        let d_binary_png = Data::Binary(Some(binary_png));

        let binary_gif = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageGIF,
        };
        let d_binary_gif = Data::Binary(Some(binary_gif));

        let binary_apng = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageAPNG,
        };
        let d_binary_apng = Data::Binary(Some(binary_apng));

        let binary_avif = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageAVIF,
        };
        let d_binary_avif = Data::Binary(Some(binary_avif));

        let binary_svg = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageSVG,
        };
        let d_binary_svg = Data::Binary(Some(binary_svg));

        let binary_webp = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::ImageWEBP,
        };
        let d_binary_webp = Data::Binary(Some(binary_webp));

        let binary_mpeg = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::VideoMPEG,
        };
        let d_binary_mpeg = Data::Binary(Some(binary_mpeg));

        let binary_mp4 = BinaryData {
            binary: "abc".to_string(),
            binary_type: BinaryType::VideoMP4,
        };
        let d_binary_mp4 = Data::Binary(Some(binary_mp4));

        assert_eq!(
            db.builder().build(Some(b"true")).unwrap().to_string(),
            db.to_string()
        );
        assert_eq!(
            du.builder().build(Some(b"10")).unwrap().to_string(),
            du.to_string()
        );
        assert_eq!(
            di.builder().build(Some(b"-10")).unwrap().to_string(),
            di.to_string()
        );
        assert_eq!(
            df.builder().build(Some(b"-10.46")).unwrap().to_string(),
            df.to_string()
        );
        assert_eq!(
            ds.builder()
                .build(Some(b"hello, world!"))
                .unwrap()
                .to_string(),
            ds.to_string()
        );
        assert_eq!(
            d_binary_jpeg
                .builder()
                .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageJPEG\"}"))
                .unwrap()
                .to_string(),
            d_binary_jpeg.to_string()
        );
        assert_eq!(
            d_binary_png
                .builder()
                .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImagePNG\"}"))
                .unwrap()
                .to_string(),
            d_binary_png.to_string()
        );
        assert_eq!(
            d_binary_gif
                .builder()
                .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageGIF\"}"))
                .unwrap()
                .to_string(),
            d_binary_gif.to_string()
        );
        assert_eq!(
            d_binary_apng
                .builder()
                .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageAPNG\"}"))
                .unwrap()
                .to_string(),
            d_binary_apng.to_string()
        );
        assert_eq!(
            d_binary_avif
                .builder()
                .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageAVIF\"}"))
                .unwrap()
                .to_string(),
            d_binary_avif.to_string()
        );
        assert_eq!(
            d_binary_svg
                .builder()
                .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageSVG\"}"))
                .unwrap()
                .to_string(),
            d_binary_svg.to_string()
        );
        assert_eq!(
            d_binary_webp
                .builder()
                .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageWEBP\"}"))
                .unwrap()
                .to_string(),
            d_binary_webp.to_string()
        );
        assert_eq!(
            d_binary_mpeg
                .builder()
                .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"VideoMPEG\"}"))
                .unwrap()
                .to_string(),
            d_binary_mpeg.to_string()
        );
        assert_eq!(
            d_binary_mp4
                .builder()
                .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"VideoMP4\"}"))
                .unwrap()
                .to_string(),
            d_binary_mp4.to_string()
        );
    }

    #[test]
    fn test_databuilder_from_typebuildercontainer_valid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Bool(BoolDataBuilder {})));
        let db: DataBuilder = tbc.try_into().unwrap();
        let d = db.build(Some(b"true")).unwrap();
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
        let d = bdb.build(Some(b"true")).unwrap();
        match d {
            Data::Bool(b) => assert_eq!(b, true),
            _ => panic!("Extracted data should have been a bool-type"),
        }
    }

    #[test]
    fn test_booldatabuilder_build_false() {
        let bdb = BoolDataBuilder {};
        let d = bdb.build(Some(b"false")).unwrap();
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
        let d = udb.build(Some(b"10")).unwrap();
        match d {
            Data::U64(n) => assert_eq!(n, 10),
            _ => panic!("Extracted data should have been a u64-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_u64databuilder_build_invalid() {
        let udb = U64DataBuilder {};
        udb.build(Some(b"-10")).unwrap();
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
        let d = udb.build(Some(b"-10")).unwrap();
        match d {
            Data::I64(n) => assert_eq!(n, -10),
            _ => panic!("Extracted data should have been a i64-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_i64databuilder_build_invalid() {
        let udb = I64DataBuilder {};
        udb.build(Some(b"-10.54")).unwrap();
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
        let d = udb.build(Some(b"-10.53")).unwrap();
        match d {
            Data::F64(n) => assert!((n + 10.53).abs() < f64::EPSILON),
            _ => panic!("Extracted data should have been a f64-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_f64databuilder_build_invalid() {
        let udb = F64DataBuilder {};
        udb.build(Some(b"somestr")).unwrap();
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
        let d = sdb.build(Some(b"hello, world!")).unwrap();
        match d {
            Data::String(s) => assert_eq!(s, "hello, world!".to_owned()),
            _ => panic!("Extracted data should have been a string-type"),
        }
    }

    #[test]
    #[should_panic]
    fn test_stringdatabuilder_build_invalid() {
        let udb = StringDataBuilder {};
        udb.build(Some(vec![0xc3, 0x28].as_ref())).unwrap();
    }

    #[test]
    fn test_stringdatabuilder_from_typebuildercontainer_valid() {
        let tbc =
            TypeBuilderContainer(TypeBuilder::Data(DataBuilder::String(StringDataBuilder {})));
        let db: StringDataBuilder = tbc.try_into().unwrap();
        let d = db.build(Some(b"hello, world!")).unwrap();
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

    #[test]
    fn test_binarydatabuilder_jpeg_build_valid() {
        let udb = BinaryDataBuilder {};
        let d = udb
            .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageJPEG\"}"))
            .unwrap();
        match d {
            Data::Binary(b) => match b {
                Some(bd) => {
                    assert_eq!(bd.binary_type, BinaryType::ImageJPEG);
                    assert_eq!(bd.binary, "abc");
                }
                _ => panic!("Extracted data should have been a binary-type"),
            },
            _ => panic!("Extracted data should have been a binary-type"),
        }
    }

    #[test]
    fn test_binarydatabuilder_png_build_valid() {
        let udb = BinaryDataBuilder {};
        let d = udb
            .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImagePNG\"}"))
            .unwrap();
        match d {
            Data::Binary(b) => match b {
                Some(bd) => {
                    assert_eq!(bd.binary_type, BinaryType::ImagePNG);
                    assert_eq!(bd.binary, "abc");
                }
                _ => panic!("Extracted data should have been a binary-type"),
            },
            _ => panic!("Extracted data should have been a binary"),
        }
    }

    #[test]
    fn test_binarydatabuilder_gif_build_valid() {
        let udb = BinaryDataBuilder {};
        let d = udb
            .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageGIF\"}"))
            .unwrap();
        match d {
            Data::Binary(b) => match b {
                Some(bd) => {
                    assert_eq!(bd.binary_type, BinaryType::ImageGIF);
                    assert_eq!(bd.binary, "abc");
                }
                _ => panic!("Extracted data should have been a binary-type"),
            },
            _ => panic!("Extracted data should have been a binary"),
        }
    }

    #[test]
    fn test_binarydatabuilder_apng_build_valid() {
        let udb = BinaryDataBuilder {};
        let d = udb
            .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageAPNG\"}"))
            .unwrap();
        match d {
            Data::Binary(b) => match b {
                Some(bd) => {
                    assert_eq!(bd.binary_type, BinaryType::ImageAPNG);
                    assert_eq!(bd.binary, "abc");
                }
                _ => panic!("Extracted data should have been a binary-type"),
            },
            _ => panic!("Extracted data should have been a binary"),
        }
    }

    #[test]
    fn test_binarydatabuilder_avif_build_valid() {
        let udb = BinaryDataBuilder {};
        let d = udb
            .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageAVIF\"}"))
            .unwrap();
        match d {
            Data::Binary(b) => match b {
                Some(bd) => {
                    assert_eq!(bd.binary_type, BinaryType::ImageAVIF);
                    assert_eq!(bd.binary, "abc");
                }
                _ => panic!("Extracted data should have been a binary-type"),
            },
            _ => panic!("Extracted data should have been a binary"),
        }
    }

    #[test]
    fn test_binarydatabuilder_svg_build_valid() {
        let udb = BinaryDataBuilder {};
        let d = udb
            .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageSVG\"}"))
            .unwrap();
        match d {
            Data::Binary(b) => match b {
                Some(bd) => {
                    assert_eq!(bd.binary_type, BinaryType::ImageSVG);
                    assert_eq!(bd.binary, "abc");
                }
                _ => panic!("Extracted data should have been a binary-type"),
            },
            _ => panic!("Extracted data should have been a binary"),
        }
    }

    #[test]
    fn test_binarydatabuilder_webp_build_valid() {
        let udb = BinaryDataBuilder {};
        let d = udb
            .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageWEBP\"}"))
            .unwrap();
        match d {
            Data::Binary(b) => match b {
                Some(bd) => {
                    assert_eq!(bd.binary_type, BinaryType::ImageWEBP);
                    assert_eq!(bd.binary, "abc");
                }
                _ => panic!("Extracted data should have been a binary-type"),
            },
            _ => panic!("Extracted data should have been a binary"),
        }
    }

    #[test]
    fn test_binarydatabuilder_mpeg_build_valid() {
        let udb = BinaryDataBuilder {};
        let d = udb
            .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"VideoMPEG\"}"))
            .unwrap();
        match d {
            Data::Binary(b) => match b {
                Some(bd) => {
                    assert_eq!(bd.binary_type, BinaryType::VideoMPEG);
                    assert_eq!(bd.binary, "abc");
                }
                _ => panic!("Extracted data should have been a binary-type"),
            },
            _ => panic!("Extracted data should have been a binary"),
        }
    }

    #[test]
    fn test_binarydatabuilder_mp4_build_valid() {
        let udb = BinaryDataBuilder {};
        let d = udb
            .build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"VideoMP4\"}"))
            .unwrap();
        match d {
            Data::Binary(b) => match b {
                Some(bd) => {
                    assert_eq!(bd.binary_type, BinaryType::VideoMP4);
                    assert_eq!(bd.binary, "abc");
                }
                _ => panic!("Extracted data should have been a binary-type"),
            },
            _ => panic!("Extracted data should have been a binary"),
        }
    }

    #[test]
    #[should_panic]
    fn test_binarydatabuilder_build_invalid() {
        let udb = BinaryDataBuilder {};
        udb.build(Some(b"-10")).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_binarydatabuilder_build_invalid_binary_type() {
        let udb = BinaryDataBuilder {};
        udb.build(Some(b"{\"binary\":\"abc\",\"binary_type\":\"ImageXYZ\"}"))
            .unwrap();
    }

    #[test]
    fn test_binarydatabuilder_from_typebuildercontainer_valid() {
        let tbc =
            TypeBuilderContainer(TypeBuilder::Data(DataBuilder::Binary(BinaryDataBuilder {})));
        let _: BinaryDataBuilder = tbc.try_into().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_binarydatabuilder_from_typebuildercontainer_invalid() {
        let tbc = TypeBuilderContainer(TypeBuilder::Key(KeyBuilder::Symmetric(
            SymmetricKeyBuilder::SodiumOxide(SodiumOxideSymmetricKeyBuilder {}),
        )));
        let _: BinaryDataBuilder = tbc.try_into().unwrap();
    }
}
