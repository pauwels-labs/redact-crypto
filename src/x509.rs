use cookie_factory::{GenResult, WriteContext};
use der::{asn1::{Any, Ia5String}, Decodable, DecodeValue, Decoder, Encodable, Length, Tag, TagMode, Sequence, Tagged};

use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use std::{
    convert::{TryFrom, TryInto},
    io::Write,
};
use x509::{
    der::Oid as OidTrait, AlgorithmIdentifier as AlgorithmIdentifierTrait,
    SubjectPublicKeyInfo as SubjectPublicKeyInfoTrait,
};

pub struct Oid(pub Vec<u64>);
impl AsRef<[u64]> for Oid {
    fn as_ref(&self) -> &[u64] {
        &self.0
    }
}
impl OidTrait for Oid {}

pub struct AlgorithmIdentifierWrapper<'a>(pub AlgorithmIdentifier<'a>);
impl<'a> AlgorithmIdentifierTrait for AlgorithmIdentifierWrapper<'a> {
    type AlgorithmOid = Oid;

    fn algorithm(&self) -> Self::AlgorithmOid {
        Oid(self.0.oid.arcs().map(|v| v as u64).collect::<Vec<u64>>())
    }

    fn parameters<W: std::io::Write>(&self, mut w: WriteContext<W>) -> GenResult<W> {
        match self.0.parameters {
            Some(p) => {
                w.write_all(p.value())?;
                Ok(w)
            }
            None => Ok(w),
        }
    }
}

pub struct SubjectPublicKeyInfoWrapper<'a>(pub SubjectPublicKeyInfo<'a>);
impl<'a> SubjectPublicKeyInfoTrait for SubjectPublicKeyInfoWrapper<'a> {
    type AlgorithmId = AlgorithmIdentifierWrapper<'a>;
    type SubjectPublicKey = &'a [u8];

    fn algorithm_id(&self) -> Self::AlgorithmId {
        AlgorithmIdentifierWrapper(self.0.algorithm)
    }

    fn public_key(&self) -> Self::SubjectPublicKey {
        self.0.subject_public_key
    }
}

pub struct DistinguishedName<'a> {
    pub o: &'a str,
    pub ou: &'a str,
    pub cn: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneralNames<'a> {
    pub sans: Vec<GeneralName<'a>>,
}

impl<'a> TryFrom<&'a [&'a str]> for GeneralNames<'a> {
    type Error = der::Error;

    fn try_from(sans: &'a [&'a str]) -> Result<Self, Self::Error> {
        let mut valid_strings = vec![];
        sans.iter().try_for_each(|san| {
            valid_strings.push(GeneralName::DnsName(Ia5String::new(*san)?));
            Ok::<_, der::Error>(())
        })?;
        Ok(Self {
            sans: valid_strings,
        })
    }
}

impl<'a> DecodeValue<'a> for GeneralNames<'a> {
    fn decode_value(decoder: &mut Decoder<'a>, _: Length) -> der::Result<Self> {
        let mut sans = vec![];
        while !decoder.is_finished() {
            let san: GeneralName = decoder.decode()?;
            sans.push(san);
        }
        Ok(Self { sans })
    }
}

impl<'a> TryFrom<Any<'a>> for GeneralNames<'a> {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> der::Result<GeneralNames<'a>> {
        any.sequence(|decoder| {
            let mut sans = vec![];
            while !decoder.is_finished() {
                let san: GeneralName = decoder.decode()?;
                sans.push(san);
            }

            Ok(Self { sans })
        })
    }
}

impl<'a> Sequence<'a> for GeneralNames<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        let mut references: Vec<&dyn Encodable> = vec![];
        for reference in self.sans.iter() {
            references.push(reference);
        }
        field_encoder(references.as_slice())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GeneralName<'a> {
    Rfc822Name(Ia5String<'a>),
    DnsName(Ia5String<'a>),
}

impl<'a> Decodable<'a> for GeneralName<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.any()?.try_into()
    }
}

impl<'a> Encodable for GeneralName<'a> {
    fn encoded_len(&self) -> der::Result<Length> {
        match self {
            GeneralName::Rfc822Name(v) => {
                TryInto::<Length>::try_into(v.as_bytes().len())?.for_tlv()
            }
            GeneralName::DnsName(v) => TryInto::<Length>::try_into(v.as_bytes().len())?.for_tlv(),
        }
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        let (tag_number, value) = match self {
            GeneralName::Rfc822Name(v) => (0x01.try_into()?, v),
            GeneralName::DnsName(v) => (0x02.try_into()?, v),
        };
        encoder.context_specific(tag_number, TagMode::Implicit, value)
    }
}

impl<'a> TryFrom<Any<'a>> for GeneralName<'a> {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> Result<Self, Self::Error> {
        match any.tag() {
            Tag::ContextSpecific { number, .. } => match number.value() {
                0x01 => Ok(GeneralName::Rfc822Name(Ia5String::new(any.value())?)),
                0x02 => Ok(GeneralName::DnsName(Ia5String::new(any.value())?)),
                _ => Err(der::ErrorKind::TagUnexpected {
                    expected: None,
                    actual: any.tag(),
                }
                .into()),
            },
            actual => Err(der::ErrorKind::TagUnexpected {
                expected: None,
                actual,
            }
            .into()),
        }
    }
}
