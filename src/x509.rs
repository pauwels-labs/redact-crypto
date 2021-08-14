// Parts of this file are pulled straight from docs.rs/der
use cookie_factory::{GenResult, WriteContext};
use core::convert::TryFrom;
use der::{
    asn1::{Any, BitString, ContextSpecific, ObjectIdentifier, SetOfRef, UtcTime, Utf8String},
    Encodable, Message,
};
use pkcs8::AlgorithmIdentifier;
use std::io::Write;
use x509::{der::Oid as OidTrait, AlgorithmIdentifier as AlgorithmIdentifierTrait};

// #[derive(Message)]
// pub struct Validity {
//     not_before: UtcTime,
//     not_after: UtcTime,
// }

// pub enum Name<'a> {
//     RelativeDistinguishedName(SetOfRef<'a, Utf8AttributeValueAssertion<'a>>),
// }

// impl<'a> TryFrom<Any<'a>> for Name<'a> {
//     type Error = der::Error;

//     fn try_from(any: Any<'a>) -> der::Result<Name> {
//         any.sequence(|decoder| {
//             let rdn = decoder.decode()?;
//             Ok(Name::RelativeDistinguishedName(rdn))
//         })
//     }
// }

// impl<'a> Message<'a> for Name<'a> {
//     fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
//     where
//         F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
//     {
//         match self {
//             Self::RelativeDistinguishedName(rdn) => field_encoder(&[rdn]),
//         }
//     }
// }

// #[derive(Clone, Ord, Eq, PartialEq, PartialOrd, Message)]
// pub struct Utf8AttributeValueAssertion<'a> {
//     type_attribute: ObjectIdentifier,
//     value_attribute: Utf8String<'a>,
// }

// #[derive(Message)]
// pub struct TbsCertificate<'a> {
//     version: ContextSpecific<'a>,
//     serial_number: u64,
//     signature: AlgorithmIdentifier<'a>,
//     issuer: Name<'a>,
//     validity: Validity,
//     subject: Name<'a>,
//     subject_public_key_info: SubjectPublicKeyInfo<'a>,
// }

// #[derive(Message)]
// pub struct Certificate<'a> {
//     tbs_certificate: TbsCertificate<'a>,
//     signature_algorithm: AlgorithmIdentifier<'a>,
//     signature_value: BitString<'a>,
// }

// #[derive(Message)]
// pub struct SubjectPublicKeyInfo<'a> {
//     pub algorithm: AlgorithmIdentifier<'a>,
//     pub subject_public_key: BitString<'a>,
// }

// #[derive(Copy, Clone, Debug, Eq, PartialEq, Message)]
// pub struct AlgorithmIdentifier<'a> {
//     pub algorithm: ObjectIdentifier,
//     pub parameters: Option<Any<'a>>,
// }

pub struct AlgorithmIdentifierWrapper<'a>(AlgorithmIdentifier<'a>);
pub struct Oid(Vec<u64>);

impl AsRef<[u64]> for Oid {
    fn as_ref(&self) -> &[u64] {
        &self.0
    }
}

impl OidTrait for Oid {}

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

#[cfg(test)]
mod tests {
    use crate::{
        key::sodiumoxide::SodiumOxideCurve25519PublicAsymmetricKey, ByteSource, HasByteSource,
        Signer,
    };
    use crate::{
        key::sodiumoxide::SodiumOxideEd25519SecretAsymmetricKey,
        x509::{
            AlgorithmIdentifier, Certificate, Name, SubjectPublicKeyInfo, TbsCertificate,
            Utf8AttributeValueAssertion, Validity,
        },
    };
    use chrono::prelude::*;
    use der::{
        asn1::{Any, BitString, ContextSpecific, SetOfRef, UtcTime, Utf8String},
        Encodable, Tag, TagNumber,
    };

    #[test]
    fn test_serialization() {
        let (x25519_pk, _) = SodiumOxideCurve25519PublicAsymmetricKey::new();
        let ed25519_sk = SodiumOxideEd25519SecretAsymmetricKey::new();
        let x25519_pk_bytes: Vec<u8> = x25519_pk.byte_source().get().unwrap().to_vec();
        let ed25519_alg_identifier = AlgorithmIdentifier {
            algorithm: "1.3.101.112".parse().unwrap(),
            parameters: None,
        };
        let x25519_alg_identifier = AlgorithmIdentifier {
            algorithm: "1.3.101.110".parse().unwrap(),
            parameters: None,
        };
        let issuer_name = Utf8AttributeValueAssertion {
            type_attribute: "2.5.4.3".parse().unwrap(),
            value_attribute: Utf8String::new("Redact").unwrap(),
        };
        let issuer_name_bytes = issuer_name.to_vec().unwrap();
        let subject_name = Utf8AttributeValueAssertion {
            type_attribute: "2.5.4.3".parse().unwrap(),
            value_attribute: Utf8String::new("Alex").unwrap(),
        };
        let subject_name_bytes = subject_name.to_vec().unwrap();

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
            signature: ed25519_alg_identifier,
            issuer: Name::RelativeDistinguishedName(
                SetOfRef::new(issuer_name_bytes.as_ref()).unwrap(),
            ),
            validity: Validity {
                not_before,
                not_after,
            },
            subject: Name::RelativeDistinguishedName(
                SetOfRef::new(subject_name_bytes.as_ref()).unwrap(),
            ),
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: x25519_alg_identifier,
                subject_public_key: BitString::new(&x25519_pk_bytes).unwrap(),
            },
        };
        let tbs_cert_encoded: Vec<u8> = tbs_cert.to_vec().unwrap();
        let tbs_cert_encoded_bs: ByteSource = AsRef::<[u8]>::as_ref(&tbs_cert_encoded).into();
        let signature = ed25519_sk.sign(tbs_cert_encoded_bs).unwrap();
        let cert = Certificate {
            tbs_certificate: tbs_cert,
            signature_algorithm: ed25519_alg_identifier,
            signature_value: BitString::new(signature.get().unwrap()).unwrap(),
        };
        let der_encoded_cert = cert.to_vec().unwrap();
        let b64_encoded_cert = base64::encode(&der_encoded_cert);
        println!("{}", b64_encoded_cert);
    }
}
