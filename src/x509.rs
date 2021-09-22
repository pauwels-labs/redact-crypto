use cookie_factory::{GenResult, WriteContext};
use der::{
    asn1::{Any, ContextSpecific, Ia5String},
    Encodable, Message, TagNumber,
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
    pub sans: Vec<Ia5String<'a>>,
}

impl<'a> TryFrom<&'a [&'a str]> for SubjectAlternativeNames<'a> {
    type Error = der::Error;

    fn try_from(sans: &'a [&'a str]) -> Result<Self, Self::Error> {
        let mut valid_strings = vec![];
        sans.iter().try_for_each(|san| {
            valid_strings.push(Ia5String::new(*san)?);
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
                let tag_number: TagNumber = 2u8.try_into()?;
                let name = decoder.context_specific(tag_number)?;
                if let Some(value) = name {
                    let name_str = value.ia5_string()?;
                    sans.push(name_str);
                }
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
        let tag_number = 2u8.try_into()?;
        let mut sans_bytes = vec![];
        self.sans.iter().try_for_each(|san| {
            println!("first line of iteration");
            let cs_bytes = ContextSpecific {
                tag_number,
                value: san.as_bytes().try_into()?,
            }
            .to_vec()?;
            println!("{:?}", cs_bytes);
            sans_bytes.extend_from_slice(cs_bytes.as_slice());
            Ok::<_, der::Error>(())
        })?;
        println!("done with iteration");
        field_encoder(&[&Any::try_from(sans_bytes.as_slice())?])
    }
}
