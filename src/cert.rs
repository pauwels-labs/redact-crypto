use crate::{
    x509::{
        AlgorithmIdentifierWrapper, DistinguishedName, Oid, GeneralNames,
        SubjectPublicKeyInfoWrapper,
    },
    CryptoError, HasAlgorithmIdentifier, HasByteSource, HasPublicKey, Signer, SourceError,
};
use chrono::prelude::*;
use rand::{thread_rng, Rng};
use sha1::{Digest, Sha1};
use std::{
    convert::TryInto,
    error::Error,
    fmt::{self, Display, Formatter},
};
use x509::Extension;
use der::Encodable;

#[derive(Debug)]
pub enum X509Error {
    /// Error happened during random number generation
    RandError { source: rand::Error },

    /// Error happened when handling a source
    SourceError { source: SourceError },

    /// Error happened during X509 serialization
    X509SerializationError { source: cookie_factory::GenError },

    /// Error happened during DER serialization
    DerSerializationError { source: der::Error },

    /// Error happened during a crypto operation
    CryptoError { source: CryptoError },

    /// Provided SAN was too long
    SanTooLong { san: String },
}

impl Error for X509Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            X509Error::RandError { ref source } => Some(source),
            X509Error::SourceError { ref source } => Some(source),
            X509Error::X509SerializationError { ref source } => Some(source),
            X509Error::CryptoError { ref source } => Some(source),
            X509Error::SanTooLong { .. } => None,
            X509Error::DerSerializationError { .. } => None,
        }
    }
}

impl Display for X509Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            X509Error::RandError { .. } => {
                write!(f, "Error occured during random number generation")
            }
            X509Error::SourceError { .. } => {
                write!(f, "Error occured while handling a source")
            }
            X509Error::X509SerializationError { .. } => {
                write!(f, "Error occured while serializing to x509")
            }
            X509Error::CryptoError { .. } => {
                write!(f, "Error occured while performing a crypto operation")
            }
            X509Error::SanTooLong { ref san } => {
                write!(f, "Provided SAN was too long: {}", san)
            }
            X509Error::DerSerializationError { source } => {
                write!(f, "{}", source)
            }
        }
    }
}

impl From<CryptoError> for X509Error {
    fn from(e: CryptoError) -> Self {
        X509Error::CryptoError { source: e }
    }
}

pub fn setup_cert<
    SK: Signer + HasPublicKey + HasByteSource + HasAlgorithmIdentifier,
    BPK: HasByteSource + HasAlgorithmIdentifier,
>(
    issuer_key: &SK,
    subject_key: Option<&BPK>,
    issuer_dn: &DistinguishedName,
    subject_dn: Option<&DistinguishedName>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    is_ca: bool,
    subject_alternative_names: Option<&[&str]>,
) -> Result<Vec<u8>, X509Error> {
    // Generate a random 20-byte serial number
    let mut serial_number: [u8; 20] = [0; 20];
    thread_rng()
        .try_fill(&mut serial_number)
        .map_err(|source| X509Error::RandError { source })?;

    // Identify the issuer key algorithm
    let signature_ai = AlgorithmIdentifierWrapper(issuer_key.algorithm_identifier());

    // Identify the subject key algorithm
    let subject_key_ai = match subject_key {
        Some(sk) => sk.algorithm_identifier(),
        None => signature_ai.0,
    };

    // Get the subject key bytes, either given or a self-signed cert
    let subject_key_bytes = match subject_key {
        Some(sk) => sk.byte_source(),
        None => issuer_key.public_key()?.byte_source(),
    };

    // Define the SPKI block of the cert
    let spki = SubjectPublicKeyInfoWrapper(spki::SubjectPublicKeyInfo {
        algorithm: subject_key_ai,
        subject_public_key: subject_key_bytes
            .get()
            .map_err(|source| X509Error::SourceError { source })?,
    });

    // Define the issuer and subject RDNs
    let issuer_rdn: [x509::RelativeDistinguishedName; 3] = [
        x509::RelativeDistinguishedName::organization(issuer_dn.o),
        x509::RelativeDistinguishedName::organizational_unit(issuer_dn.ou),
        x509::RelativeDistinguishedName::common_name(issuer_dn.cn),
    ];
    let subject_rdn: [x509::RelativeDistinguishedName; 3] = [
        x509::RelativeDistinguishedName::organization(match subject_dn {
            Some(dn) => dn.o,
            None => issuer_dn.o,
        }),
        x509::RelativeDistinguishedName::organizational_unit(match subject_dn {
            Some(dn) => dn.ou,
            None => issuer_dn.ou,
        }),
        x509::RelativeDistinguishedName::common_name(match subject_dn {
            Some(dn) => dn.cn,
            None => issuer_dn.cn,
        }),
    ];

    // Define x509v3 extensions
    let mut sha1hasher = Sha1::new();
    let mut extensions: Vec<Extension<Oid>> = vec![];

    // Subject key identifier
    let subject_key_identifier_oid: Oid = Oid(vec![2, 5, 29, 14]);
    sha1hasher.update(
        subject_key_bytes
            .get()
            .map_err(|source| X509Error::SourceError { source })?,
    );
    let subject_key_hash = &sha1hasher.finalize_reset()[..];
    let mut subject_key_identifier_value: Vec<u8> = vec![0x4, 0x14];
    subject_key_identifier_value.extend_from_slice(subject_key_hash);
    let ext_subject_key_identifier = Extension::regular(
        subject_key_identifier_oid,
        subject_key_identifier_value.as_slice(),
    );
    extensions.push(ext_subject_key_identifier);

    // Authority key identifier
    let mut authority_key_identifier_value: Vec<u8> = vec![0x30, 0x16, 0x80, 0x14];
    if subject_key.is_some() {
        sha1hasher.update(
            issuer_key
                .public_key()?
                .byte_source()
                .get()
                .map_err(|source| X509Error::SourceError { source })?,
        );
        let issuer_key_hash = &sha1hasher.finalize_reset()[..];
        authority_key_identifier_value.extend_from_slice(issuer_key_hash);
        let authority_key_identifier_oid: Oid = Oid(vec![2, 5, 29, 35]);
        let ext_authority_key_identifier = Extension::regular(
            authority_key_identifier_oid,
            authority_key_identifier_value.as_slice(),
        );
        extensions.push(ext_authority_key_identifier);
    }

    // Basic constraints
    let basic_constraints_oid: Oid = Oid(vec![2, 5, 29, 19]);
    let mut basic_constraints_value: Vec<u8> = vec![0x30];
    if is_ca {
        basic_constraints_value.extend_from_slice(&[0x03, 0x01, 0x01, 0xFF]);
    } else {
        basic_constraints_value.extend_from_slice(&[0x00]);
    }
    let ext_basic_constraints =
        Extension::critical(basic_constraints_oid, basic_constraints_value.as_slice());
    extensions.push(ext_basic_constraints);

    // Key usage
    let key_usage_oid: Oid = Oid(vec![2, 5, 29, 15]);
    let mut key_usage_value: Vec<u8> = vec![0x03, 0x02];
    if is_ca {
        key_usage_value.extend_from_slice(&[0x01, 0x06]);
    } else {
        key_usage_value.extend_from_slice(&[0x05, 0xA0]);
    }
    let ext_key_usage = Extension::critical(key_usage_oid, key_usage_value.as_slice());
    extensions.push(ext_key_usage);

    // Extended key usage
    let mut extended_key_usage_value: Vec<u8> = vec![0x30, 0x14];
    if !is_ca {
        let extended_key_usage_oid: Oid = Oid(vec![2, 5, 29, 37]);
        extended_key_usage_value.extend_from_slice(&[
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06,
            0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
        ]);
        let ext_extended_key_usage =
            Extension::regular(extended_key_usage_oid, extended_key_usage_value.as_slice());
        extensions.push(ext_extended_key_usage);
    }

    // SANs
    let mut sans_value = vec![];
    if let Some(sans) = subject_alternative_names {
        let sans: GeneralNames = sans
            .try_into()
            .map_err(|e| X509Error::DerSerializationError { source: e })?;
        let sans_oid: Oid = Oid(vec![2, 5, 29, 17]);
        let sans_bytes = sans
            .to_vec()
            .map_err(|e| X509Error::DerSerializationError { source: e })?;
        sans_value.extend_from_slice(sans_bytes.as_slice());
        let ext_sans = Extension::regular(sans_oid, sans_value.as_slice());
        extensions.push(ext_sans);
    }

    // To-be-signed certificate bytes will be serialized into this vector
    let tbs_cert_vec: Vec<u8> = vec![];

    // Create the serialization function for the TBS certificate
    let tbs_cert_fn = x509::write::tbs_certificate(
        &serial_number,
        &signature_ai,
        &issuer_rdn,
        not_before,
        Some(not_after),
        &subject_rdn,
        &spki,
        extensions.as_slice(),
    );

    // Generate the TBS cert bytes and write them to the vector
    let (tbs_cert_vec, _) = tbs_cert_fn(tbs_cert_vec.into())
        .map_err(|source| X509Error::X509SerializationError { source })?
        .into_inner();

    // Sign the TBS cert
    let signature = issuer_key.sign(tbs_cert_vec.as_slice().into())?;

    // Final certificate will be serialized into this vector
    let cert_vec: Vec<u8> = vec![];

    // Create the serialization function for the final certificate from the TBS
    // certificate and the signature
    let cert_fn = x509::write::certificate(
        &tbs_cert_vec,
        &signature_ai,
        signature
            .get()
            .map_err(|source| X509Error::SourceError { source })?,
    );

    // Generate the final certificate bytes and write them to the vector
    let (cert_vec, _) = cert_fn(cert_vec.into())
        .map_err(|source| X509Error::X509SerializationError { source })?
        .into_inner();
    Ok(cert_vec)
}
