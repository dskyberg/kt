use anyhow::Result;
//use log::{info, trace};
use pkcs8::der::Document;

use pkcs1::{RsaPrivateKeyDocument, RsaPublicKeyDocument};
use pkcs8::{DecodePrivateKey, EncryptedPrivateKeyDocument, PrivateKeyDocument, PublicKeyDocument};

use sec1::{DecodeEcPrivateKey, EcPrivateKeyDocument};

use crate::app_state::AppState;
use crate::document::{
    pkcs1_docs::{rsa_private_key, rsa_public_key},
    pkcs8_docs::{pk8_encrypted_private_key_info, pk8_private_key_info},
    sec1_docs::sec1_private_key_info,
    spki_docs::spki_to_key_info,
};
use crate::errors::Error;
use crate::key_info::KeyInfo;
use crate::key_info::Encoding;


fn discover_private_key(app_state: &AppState, key_bytes: &[u8]) -> Result<KeyInfo> {
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

fn discover_public_key(key_bytes: &[u8]) -> Result<KeyInfo> {
    // Test for PEM encoding
    if let Ok(pem) = std::str::from_utf8(key_bytes) {
        if let Ok(spki_doc) = PublicKeyDocument::from_pem(pem) {
            return spki_to_key_info(&spki_doc, Encoding::PEM);
        }

        if let Ok(pk1_doc) = RsaPublicKeyDocument::from_pem(pem) {
            return rsa_public_key(&pk1_doc, Encoding::PEM);
        }
    }

    if let Ok(spki_doc) = PublicKeyDocument::from_der(key_bytes) {
        return spki_to_key_info(&spki_doc, Encoding::DER);
    }

    if let Ok(pk1_doc) = RsaPublicKeyDocument::from_der(key_bytes) {
        return rsa_public_key(&pk1_doc, Encoding::DER);
    }

    Err(Error::UnknownKeyType.into())
}

pub fn discover(app_state: &mut AppState) -> Result<KeyInfo> {

    let in_bytes = app_state.read_stream()?;

    let unknown_type = |_| -> Result<KeyInfo> { Err(Error::UnknownKeyType.into())}; 
    // Calling discover_private_key with some forms of a public key causes
    // the pkcs8 crate to panic.  Until that's fixed, just call this first.
    let result = discover_public_key(&in_bytes)
    .or_else(|_| discover_private_key(app_state, &in_bytes))
    .or_else(unknown_type)?;

    // Make sure the app_state defaults align correctly
    if app_state.alg.is_none() {
        app_state.alg = Some(result.alg);
    } 
    if app_state.key_type.is_none() {
        app_state.key_type = Some(result.key_type);
    }
    if app_state.format.is_none() {
        app_state.format = Some(result.format);
    }
    Ok(result)
}
