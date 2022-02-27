//! Utility methods for [pkcs8::AlgorithmIdentifier] management
//! 
//use std::convert::TryFrom;
use anyhow::Result;
use der::{Any, Tag};
use pkcs1::ObjectIdentifier;
use pkcs8::der::Encodable;
use pkcs8::AlgorithmIdentifier;

use crate::oids::*;

/// Create an AlgorithmIdentifier with NULL parameters
pub fn alg_id_any<'a>(oid: ObjectIdentifier) -> Result<AlgorithmIdentifier<'a>> {
    let alg_id = AlgorithmIdentifier {
        oid,
        parameters: Some(Any::NULL),
    };
    Ok(alg_id)

}

/// Create an AlgorithmIdentifier with an ObjectIdentifier as a parameter
/// Most commonly used for Elliptic Curve key formats, where the curve is
/// represented with an ObjectIdentifier
pub fn alg_id_with_oid_param(oid: ObjectIdentifier, params: &'_ [u8]) -> Result<AlgorithmIdentifier<'_>> {
    let alg_id = AlgorithmIdentifier {
        oid,
        parameters: Some(Any::new(Tag::ObjectIdentifier, params)?),
    };
    Ok(alg_id)

}

pub fn rsa_encryption<'a>() -> Result<AlgorithmIdentifier<'a>> {
    alg_id_any(RSA_ENCRYPTION)
}

pub fn rsapss_encryption<'a>() -> Result<AlgorithmIdentifier<'a>> {
    alg_id_any(RSASSA_PSS)
}

pub fn ec_encryption(curve: &'_ [u8]) -> Result<AlgorithmIdentifier<'_>> {
    alg_id_with_oid_param(ECDSA, curve)
}

/// Get the parameter bits from an AlgorithmIdentifier
pub fn alg_params(alg_id: &AlgorithmIdentifier) -> Option<Vec<u8>> {
    if let Some(params) = alg_id.parameters {
        if let Ok(bytes) = params.to_vec() {
            return Some(bytes);
        }
    }
    None
}
