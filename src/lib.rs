use anyhow::Result;
use log::trace;
use pkcs8::der::Document;
use std::path::Path;
use std::str::FromStr;

use pkcs1::{RsaPrivateKeyDocument, RsaPublicKeyDocument};
use pkcs8::{DecodePrivateKey, EncryptedPrivateKeyDocument, PrivateKeyDocument, PublicKeyDocument};

use sec1::{DecodeEcPrivateKey, EcPrivateKeyDocument};

use crate::app_state::{Alg, AppState, Encoding, KeyType};
use crate::document::{
    pkcs1_docs::{rsa_private_key, rsa_public_key},
    pkcs8_docs::{pk8_encrypted_private_key_info, pk8_private_key_info},
    sec1_docs::sec1_private_key_info,
    spki_docs::spki_public_key_info,
};
use crate::errors::Error;
use crate::key_info::KeyInfo;

pub mod alg_id;
pub mod app_state;
pub mod cli;
pub mod document;
pub mod errors;
pub mod key_info;
pub mod keypair;
pub mod oids;

/// Return PEM, DER, JWK based only on the path extension.  Note, this is likely
/// to return nothing.
pub fn guess_encoding_from_path(path: &Path) -> Option<Encoding> {
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap();
        let e = Encoding::from_str(ext);
        match e {
            Ok(encoding) => return Some(encoding),
            _ => return None,
        }
    }
    None
}

fn try_private_key(app_state: &AppState, key_bytes: &[u8]) -> Result<KeyInfo> {
    // Test for PEM encoding
    if let Ok(pem) = std::str::from_utf8(key_bytes) {
        // Test PKCS8
        if let Ok(pk8_doc) = PrivateKeyDocument::from_pkcs8_pem(pem) {
            return pk8_private_key_info(&pk8_doc, Encoding::PEM);
        }

        // Try encrypted
        if let Ok(enc_doc) = EncryptedPrivateKeyDocument::from_pem(pem) {
            return pk8_encrypted_private_key_info(app_state, &enc_doc, Encoding::PEM);
        }

        // Test PKCS1
        if let Ok(pk1_doc) = RsaPrivateKeyDocument::from_pem(pem) {
            return rsa_private_key(&pk1_doc, Encoding::PEM);
        }
        if let Ok(sec1_doc) = EcPrivateKeyDocument::from_sec1_pem(pem) {
            return sec1_private_key_info(&sec1_doc, Encoding::PEM);
        }
    }

    // Test for PKCS8 DER
    if let Ok(pk8_doc) = PrivateKeyDocument::from_der(key_bytes) {
        return pk8_private_key_info(&pk8_doc, Encoding::DER);
    }

    if let Ok(enc_doc) = EncryptedPrivateKeyDocument::from_der(key_bytes) {
        return pk8_encrypted_private_key_info(app_state, &enc_doc, Encoding::DER);
    }

    if let Ok(pk1_doc) = RsaPrivateKeyDocument::from_der(key_bytes) {
        return rsa_private_key(&pk1_doc, Encoding::DER);
    }

    if let Ok(sec1_doc) = EcPrivateKeyDocument::from_sec1_der(key_bytes) {
        return sec1_private_key_info(&sec1_doc, Encoding::DER);
    }

    Err(Error::UnknownKeyType.into())
}

fn try_public_key(key_bytes: &[u8]) -> Result<KeyInfo> {
    // Test for PEM encoding
    if let Ok(pem) = std::str::from_utf8(key_bytes) {
        if let Ok(spki_doc) = PublicKeyDocument::from_pem(pem) {
            return spki_public_key_info(&spki_doc, Encoding::PEM);
        }

        if let Ok(pk1_doc) = RsaPublicKeyDocument::from_pem(pem) {
            return rsa_public_key(&pk1_doc, Encoding::PEM);
        }
    }

    if let Ok(spki_doc) = PublicKeyDocument::from_der(key_bytes) {
        return spki_public_key_info(&spki_doc, Encoding::DER);
    }

    if let Ok(pk1_doc) = RsaPublicKeyDocument::from_der(key_bytes) {
        return rsa_public_key(&pk1_doc, Encoding::DER);
    }

    Err(Error::UnknownKeyType.into())
}

pub fn discover(app_state: &mut AppState) -> Result<KeyInfo> {
    let in_bytes = app_state.read_stream()?;
    let mut result = try_public_key(&in_bytes);
    if result.is_ok() {
        return Ok(result.unwrap());
    }
    result = try_private_key(app_state, &in_bytes);
    if result.is_ok() {
        return Ok(result.unwrap());
    }
    Err(Error::UnknownKeyType.into())
}

fn convert_rsa_private(_app_state: &AppState, _key_info: &KeyInfo) -> Result<()> {
    trace!("Converting RSA Private");
    Ok(())
}
fn convert_rsa_public(_app_state: &AppState, _key_info: &KeyInfo) -> Result<()> {
    trace!("Converting RSA Private");
    Ok(())
}

// Make sure the type of key provided can be converted to the type of key
// requested
fn compare_key_type(ki_type: Option<KeyType>, as_type: KeyType) -> Result<bool> {
    let ki_type = ki_type.ok_or_else(|| {
        trace!("No KeyType for KeyInfo");
        Error::KeyTypeError
    })?;

    if ki_type == KeyType::Public && as_type != KeyType::Public {
        println!("Cannot convert from public key to private key");
        return Err(Error::TypeMismatch.into());
    }

    Ok(true)
}

fn compare_algs(ki_alg: Option<Alg>, as_alg: Alg) -> Result<bool> {
    let ki_alg = ki_alg.ok_or_else(|| {
        trace!("No Alg for KeyInfo");
        Error::AlgError
    })?;

    match (ki_alg, as_alg) {
        (Alg::Rsa | Alg::RsaSsaPss, Alg::Rsa | Alg::RsaSsaPss) => Ok(true),
        (Alg::Ecdsa, Alg::Ecdsa) => Ok(true),
        _ => Ok(false)
    }
}

fn safe_to_convert<'a>(
    app_state: &'a AppState,
    key_info: &'a KeyInfo,
) -> Result<(&'a AppState, &'a KeyInfo)> {
    let kt = key_info.key_type().as_ref();
    let key_type = compare_key_type(kt, app_state.out_params.key_type)?;

    Ok((app_state, key_info))
}

fn do_conversion<'a>(params: (&AppState, &KeyInfo)) -> Result<()> {
    let app_state = params.0;
    let key_info = params.1;
    match (app_state.alg, app_state.in_params.key_type) {
        (Alg::Rsa | Alg::RsaSsaPss, KeyType::Private) => convert_rsa_private(app_state, key_info),
        (Alg::Rsa, KeyType::Public) => convert_rsa_public(app_state, key_info),

        _ => Err(Error::NotSupported.into()),
    }
}

/// Consume the AppState to convert the input file.
///
/// This is the main engine of the app. It processes the AppState to queue up
/// the working functions.
/// Note:  Only RSA Private keys are supported.  Elliptic Curve and Public keys
/// are on the way.
pub fn convert(app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    safe_to_convert(app_state, key_info).and_then(do_conversion)
}

pub fn show(_app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    println!("{:}", key_info);
    Ok(())
}
