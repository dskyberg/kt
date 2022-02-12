use crate::oids::*;
use anyhow::Result;
use der::{Any, Tag};
use pkcs8::der::Encodable;
use pkcs8::AlgorithmIdentifier;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;

pub const ALG_ID_RSA_ENCRYPTION: [u8; 15] =
    [48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0];

pub fn capture_alg<'a>(alg_id: &'a AlgorithmIdentifier) -> Result<Vec<u8>> {
    let bytes = alg_id.to_vec()?;
    let mut file = File::create("tmp.alg_id.bin")?;
    file.write_all(&bytes)?;
    Ok(bytes)
}

pub fn make_alg_id(bytes: &[u8]) -> Result<AlgorithmIdentifier> {
    let result = AlgorithmIdentifier::try_from(bytes);
    match result {
        Ok(alg_id) => {
            println!("Oh, yeah!!");
            Ok(alg_id)
        }
        Err(x) => Err(x.into()),
    }
}

pub fn rsa_encryption<'a>() -> Result<AlgorithmIdentifier<'a>> {
    let alg_id = AlgorithmIdentifier {
        oid: RSA_ENCRYPTION.clone(),
        parameters: Some(Any::NULL),
    };
    Ok(alg_id)
}

pub fn rsapss_encryption<'a>() -> Result<AlgorithmIdentifier<'a>> {
    let alg_id = AlgorithmIdentifier {
        oid: RSASSA_PSS.clone(),
        parameters: Some(Any::NULL),
    };
    Ok(alg_id)
}

pub fn ec_encryption<'a>(curve: &'a [u8]) -> Result<AlgorithmIdentifier<'a>> {
    // Make an OID
    // let x = PRIME_256_V1.to_vec()?;

    let alg_id = AlgorithmIdentifier {
        oid: ECDSA.clone(),
        parameters: Some(Any::new(Tag::ObjectIdentifier, curve)?),
    };
    Ok(alg_id)
}
