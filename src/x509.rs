// Parts of this file are pulled straight from docs.rs/der
use core::convert::TryFrom;
use der::{
    asn1::{Any, ContextSpecific, ObjectIdentifier, OctetString, SetOfRef, UtcTime, Utf8String},
    Choice, Encodable, Message,
};

pub struct Validity {
    not_before: UtcTime,
    not_after: UtcTime,
}

impl<'a> TryFrom<Any<'a>> for Validity {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> der::Result<Validity> {
        any.sequence(|decoder| {
            let not_before = decoder.decode()?;
            let not_after = decoder.decode()?;
            Ok(Self {
                not_before,
                not_after,
            })
        })
    }
}

impl<'a> Message<'a> for Validity {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.not_before, &self.not_after])
    }
}

// pub struct SetOfNames<'a> {
//     names: SetOfRef<'a, Name<'a>>,
// }

// impl<'a> TryFrom<Any<'a>> for SetOfNames<'a> {
//     type Error = der::Error;

//     fn try_from(any: Any<'a>) -> der::Result<SetOfNames> {
//         any.sequence(|decoder| {
//             let names = decoder.decode()?;
//             Ok(Self { names })
//         })
//     }
// }

// impl<'a> Message<'a> for SetOfNames<'a> {
//     fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
//     where
//         F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
//     {
//         field_encoder(&[&self.names])
//     }
// }

// #[derive(Clone, Ord, Eq, PartialEq, PartialOrd)]
// pub struct Name<'a> {
//     identifier: ObjectIdentifier,
//     value: Utf8String<'a>,
// }
pub enum Name<'a> {
    RdnSequence(RelativeDistinguishedName<'a>),
}

impl<'a> Choice<'a> for Name<'a> {
    fn can_decode(tag: der::Tag) -> bool {
        tag == der::Tag::Sequence
    }
}

pub struct RelativeDistinguishedName<'a> {
    names: SetOfRef<'a, Utf8AttributeValueAssertion<'a>>,
}

pub struct Utf8AttributeValueAssertion<'a> {
    type_attribute: ObjectIdentifier,
    value_attribute: Utf8String<'a>,
}

impl<'a> TryFrom<Any<'a>> for Name<'a> {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> der::Result<Name> {
        any.sequence(|decoder| {
            let identifier = decoder.decode()?;
            let value = decoder.decode()?;
            Ok(Self { identifier, value })
        })
    }
}

impl<'a> Message<'a> for Name<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.identifier, &self.value])
    }
}

pub struct TbsCertificate<'a> {
    version: ContextSpecific<'a>,
    serial_number: u64,
    signature: AlgorithmIdentifier<'a>,
    issuer: SetOfNames<'a>,
    validity: Validity,
    subject: SetOfNames<'a>,
    //subject_public_key_info:
}

impl<'a> TryFrom<Any<'a>> for TbsCertificate<'a> {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> der::Result<TbsCertificate> {
        any.sequence(|decoder| {
            let version = decoder.decode()?;
            let serial_number = decoder.decode()?;
            let signature = decoder.decode()?;
            let issuer = decoder.decode()?;
            let validity = decoder.decode()?;
            let subject = decoder.decode()?;
            Ok(Self {
                version,
                serial_number,
                signature,
                issuer,
                validity,
                subject,
            })
        })
    }
}

impl<'a> Message<'a> for TbsCertificate<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[
            &self.version,
            &self.serial_number,
            &self.signature,
            &self.issuer,
            &self.validity,
            &self.subject,
        ])
    }
}

pub struct Certificate<'a> {
    tbs_certificate: TbsCertificate<'a>,
}

impl<'a> TryFrom<Any<'a>> for Certificate<'a> {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> der::Result<Certificate> {
        any.sequence(|decoder| {
            let tbs_certificate = decoder.decode()?;
            Ok(Self { tbs_certificate })
        })
    }
}

impl<'a> Message<'a> for Certificate<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.tbs_certificate])
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PrivateKeyInfo<'a> {
    pub version: u64,
    pub private_key_algorithm: AlgorithmIdentifier<'a>,
    pub private_key: OctetString<'a>,
}

impl<'a> TryFrom<Any<'a>> for PrivateKeyInfo<'a> {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> der::Result<PrivateKeyInfo> {
        any.sequence(|decoder| {
            let version = decoder.decode()?;
            let private_key_algorithm = decoder.decode()?;
            let private_key = decoder.decode()?;
            Ok(Self {
                version,
                private_key_algorithm,
                private_key,
            })
        })
    }
}

impl<'a> Message<'a> for PrivateKeyInfo<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[
            &self.version,
            &self.private_key_algorithm,
            &self.private_key,
        ])
    }
}

/// X.509 `AlgorithmIdentifier`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AlgorithmIdentifier<'a> {
    /// This field contains an ASN.1 `OBJECT IDENTIFIER`, a.k.a. OID.
    pub algorithm: ObjectIdentifier,

    /// This field is `OPTIONAL` and contains the ASN.1 `ANY` type, which
    /// in this example allows arbitrary algorithm-defined parameters.
    pub parameters: Option<Any<'a>>,
}

impl<'a> TryFrom<Any<'a>> for AlgorithmIdentifier<'a> {
    type Error = der::Error;

    fn try_from(any: Any<'a>) -> der::Result<AlgorithmIdentifier> {
        any.sequence(|decoder| {
            let algorithm = decoder.decode()?;
            let parameters = decoder.decode()?;
            Ok(Self {
                algorithm,
                parameters,
            })
        })
    }
}

impl<'a> Message<'a> for AlgorithmIdentifier<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.algorithm, &self.parameters])
    }
}

#[cfg(test)]
mod tests {
    use crate::x509::{
        AlgorithmIdentifier, Certificate, Name, PrivateKeyInfo, SetOfNames, TbsCertificate,
        Validity,
    };
    use chrono::prelude::*;
    use der::{
        asn1::{Any, ContextSpecific, OctetString, SetOfRef, UtcTime, Utf8String},
        Decodable, Encodable, Tag, TagNumber,
    };

    #[test]
    fn test_serialization() {
        let algorithm_identifier = AlgorithmIdentifier {
            algorithm: "1.3.101.112".parse().unwrap(),
            parameters: None,
        };
        let key_bytes: [u8; 32] = [
            0xD4, 0xEE, 0x72, 0xDB, 0xF9, 0x13, 0x58, 0x4A, 0xD5, 0xB6, 0xD8, 0xF1, 0xF7, 0x69,
            0xF8, 0xAD, 0x3A, 0xFE, 0x7C, 0x28, 0xCB, 0xF1, 0xD4, 0xFB, 0xE0, 0x97, 0xA8, 0x8F,
            0x44, 0x75, 0x58, 0x42,
        ];
        let inner_key = OctetString::new(&key_bytes).unwrap().to_vec().unwrap();
        let encapsulated_key = OctetString::new(&inner_key).unwrap();
        let private_key_info = PrivateKeyInfo {
            version: 0,
            private_key_algorithm: algorithm_identifier,
            private_key: encapsulated_key,
        };
        let der_encoded_pki = private_key_info.to_vec().unwrap();
        let b64_encoded = base64::encode(&der_encoded_pki);
        println!("{}", b64_encoded);
        let decoded_pki = PrivateKeyInfo::from_der(&der_encoded_pki).unwrap();
        assert_eq!(private_key_info, decoded_pki);

        let issuer_name = Name {
            identifier: "2.5.4.3".parse().unwrap(),
            value: Utf8String::new("Redact").unwrap(),
        };
        let issuer_name_bytes = name.to_vec().unwrap();
        let not_before = UtcTime::new(
            Utc.ymd(2020, 1, 1)
                .signed_duration_since(Utc.ymd(1970, 1, 1))
                .to_std()
                .unwrap(),
        )
        .unwrap();
        let not_after = UtcTime::new(
            Utc.ymd(2029, 12, 31)
                .and_hms(23, 59, 59)
                .signed_duration_since(Utc.ymd(1970, 1, 1).and_hms(0, 0, 0))
                .to_std()
                .unwrap(),
        )
        .unwrap();
        let tbs_cert = TbsCertificate {
            version: ContextSpecific {
                tag_number: TagNumber::new(0u8),
                value: Any::new(Tag::Integer, &[2u8]).unwrap(),
            },
            serial_number: 10u64,
            signature: algorithm_identifier,
            issuer: SetOfNames {
                names: SetOfRef::new(name_bytes.as_ref()).unwrap(),
            },
            validity: Validity {
                not_before,
                not_after,
            },
            subject: SetOfNames {
                names: SetOfRef::new(),
            },
        };
        let cert = Certificate {
            tbs_certificate: tbs_cert,
        };
        let der_encoded_cert = cert.to_vec().unwrap();
        let b64_encoded_cert = base64::encode(&der_encoded_cert);
        println!("{}", b64_encoded_cert);
    }
}

// 111000011011010100001101111111_2
// 111000011011010100001110000000_2
