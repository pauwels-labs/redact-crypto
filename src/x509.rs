use cookie_factory::{GenResult, WriteContext};
use der::{
    asn1::{Any, ContextSpecific, Ia5String},
    Encodable, Message, Tag,
};
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
                w.write_all(p.as_bytes())?;
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
pub struct SubjectAlternativeNames<'a> {
    pub sans: Vec<GeneralName<'a>>,
}

impl<'a> TryFrom<&'a [&'a str]> for SubjectAlternativeNames<'a> {
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

impl<'a> TryFrom<Any<'a>> for SubjectAlternativeNames<'a> {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> der::Result<SubjectAlternativeNames<'a>> {
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

impl<'a> Message<'a> for SubjectAlternativeNames<'a> {
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
    Rfc822Name(der::asn1::Ia5String<'a>),
    DnsName(der::asn1::Ia5String<'a>),
}

impl<'a> Encodable for GeneralName<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let (tag_number, value) = match self {
            GeneralName::Rfc822Name(v) => (0x01.try_into()?, v.as_bytes()),
            GeneralName::DnsName(v) => (0x02.try_into()?, v.as_bytes()),
        };
        let len = ContextSpecific::new(tag_number, false, value)?.encoded_len();
        len
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        let (tag_number, value) = match self {
            GeneralName::Rfc822Name(v) => (0x01.try_into()?, v.as_bytes()),
            GeneralName::DnsName(v) => (0x02.try_into()?, v.as_bytes()),
        };
        ContextSpecific::new(tag_number, false, value)?.encode(encoder)
    }
}

impl<'a> TryFrom<Any<'a>> for GeneralName<'a> {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> Result<Self, Self::Error> {
        match any.tag() {
            Tag::ContextSpecific { number, .. } => match number.value() {
                0x01 => Ok(GeneralName::Rfc822Name(Ia5String::new(any.as_bytes())?)),
                0x02 => Ok(GeneralName::DnsName(Ia5String::new(any.as_bytes())?)),
                _ => Err(der::ErrorKind::UnexpectedTag {
                    expected: None,
                    actual: any.tag(),
                }
                .into()),
            },
            actual => Err(der::ErrorKind::UnexpectedTag {
                expected: None,
                actual,
            }
            .into()),
        }
    }
}
