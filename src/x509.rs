use cookie_factory::{GenResult, WriteContext};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use std::io::Write;
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
