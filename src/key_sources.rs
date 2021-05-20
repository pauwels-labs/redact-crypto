use crate::error::CryptoError;
use serde::{
    de::{self, Deserialize as DeserializeTrait, Deserializer, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use std::{convert::TryFrom, fmt, io::ErrorKind};

/// Enumerates all the different types of key sources.
/// Currently supported:
/// - Bytes: key sources that can be deserialized to a byte array
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeySources {
    Bytes(BytesKeySources),
}

/// Enumerates all the different types of byte-type key sources.
/// Currently supported:
/// - Fs: keys represented as files on the filesystem
/// - Vector: keys represented as a vector of bytes
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BytesKeySources {
    Fs(FsBytesKeySource),
    Vector(VectorBytesKeySource),
}

impl BytesKeySources {
    /// Sets the bytes of the key to the given value
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        match self {
            BytesKeySources::Fs(fsbks) => fsbks.set(key),
            BytesKeySources::Vector(vbks) => vbks.set(key),
        }
    }

    /// Gets the byte array of the key
    pub fn get(&self) -> Result<&[u8], CryptoError> {
        match self {
            BytesKeySources::Fs(fsbks) => fsbks.get(),
            BytesKeySources::Vector(vbks) => vbks.get(),
        }
    }
}

/// A key source where the key is a path to a file on the filesystem
#[derive(Serialize, Debug, Clone)]
pub struct FsBytesKeySource {
    path: String,
    #[serde(skip)]
    cached: Option<VectorBytesKeySource>,
}

impl<'de> DeserializeTrait<'de> for FsBytesKeySource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Path,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`path`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "path" => Ok(Field::Path),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct FsBytesKeySourceVisitor;

        impl<'de> Visitor<'de> for FsBytesKeySourceVisitor {
            type Value = FsBytesKeySource;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct FsBytesKeySource")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let path = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                FsBytesKeySource::new(path).map_err(de::Error::custom)
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut path: Option<String> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Path => {
                            if path.is_some() {
                                return Err(de::Error::duplicate_field("path"));
                            }
                            path = Some(map.next_value()?);
                        }
                    }
                }
                let path = path.ok_or_else(|| de::Error::missing_field("path"))?;
                FsBytesKeySource::new(&path).map_err(de::Error::custom)
            }
        }

        const FIELDS: &'static [&'static str] = &["secs", "nanos"];
        deserializer.deserialize_struct("Duration", FIELDS, FsBytesKeySourceVisitor)
    }
}

impl FsBytesKeySource {
    /// Creates an `FsBytesKeySources` from a path on the filesystem
    pub fn new(path: &str) -> Result<Self, CryptoError> {
        match Self::read_from_path(path) {
            Ok(vbks) => Ok(Self {
                path: path.to_owned(),
                cached: Some(vbks),
            }),
            Err(e) => match e {
                CryptoError::NotFound => Ok(Self {
                    path: path.to_owned(),
                    cached: None,
                }),
                _ => Err(e),
            },
        }
    }

    /// Reads a `VectorBytesKeySources` from a pathh on the filesystem
    fn read_from_path(path: &str) -> Result<VectorBytesKeySource, CryptoError> {
        // Mock this
        let read_bytes = std::fs::read(path).map_err(|e| match e.kind() {
            ErrorKind::NotFound => CryptoError::NotFound,
            _ => CryptoError::FsIoError { source: e },
        })?;
        Ok(VectorBytesKeySource {
            value: Some(read_bytes),
        })
    }

    /// Re-reads the file and stores its bytes in memory
    pub fn reload(&mut self) -> Result<(), CryptoError> {
        self.cached = Some(Self::read_from_path(&self.path)?);
        Ok(())
    }

    /// Re-writes the key to be the given bytes
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        std::fs::write(&self.path, key)
            .map(|_| self.reload())
            .map_err(|source| match source.kind() {
                std::io::ErrorKind::NotFound => CryptoError::NotFound,
                _ => CryptoError::FsIoError { source },
            })?
    }

    /// Returns the key as a byte array
    pub fn get(&self) -> Result<&[u8], CryptoError> {
        match self.cached {
            Some(ref vbks) => vbks.get(),
            None => Err(CryptoError::NotFound),
        }
    }

    /// Returns the path where the key is stored
    pub fn get_path(&self) -> &str {
        &self.path
    }
}

/// A key source where the key is an array of bytes in memory
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VectorBytesKeySource {
    value: Option<Vec<u8>>,
}

impl VectorBytesKeySource {
    /// Creates a new `VectorBytesKeySources` from the given byte array
    pub fn new(bytes: Option<&[u8]>) -> Self {
        VectorBytesKeySource {
            value: bytes.map(|bytes| bytes.to_vec()),
        }
    }

    /// Re-writes the key to be the given bytes
    pub fn set(&mut self, key: &[u8]) -> Result<(), CryptoError> {
        self.value = Some(key.to_vec());
        Ok(())
    }

    /// Returns the key as an array of bytes
    pub fn get(&self) -> Result<&[u8], CryptoError> {
        match self.value {
            Some(ref v) => Ok(&v),
            None => Err(CryptoError::NotFound),
        }
    }
}

impl TryFrom<KeySources> for BytesKeySources {
    type Error = CryptoError;

    fn try_from(ks: KeySources) -> Result<Self, Self::Error> {
        match ks {
            KeySources::Bytes(bks) => Ok(bks),
        }
    }
}

impl TryFrom<&KeySources> for BytesKeySources {
    type Error = CryptoError;

    fn try_from(ks: &KeySources) -> Result<Self, Self::Error> {
        match ks {
            KeySources::Bytes(bks) => match bks {
                BytesKeySources::Fs(fsbks) => Ok(BytesKeySources::Fs(fsbks.clone())),
                BytesKeySources::Vector(vbks) => Ok(BytesKeySources::Vector(vbks.clone())),
            },
        }
    }
}
