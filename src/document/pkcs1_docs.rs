use anyhow::Result;

use pkcs8::{der::Document, LineEnding::CRLF};
use pkcs1::{RsaPrivateKeyDocument, RsaPublicKeyDocument};

use crate::app_state::AppState;
use crate::key_info::KeyInfo;
use crate::key_info::{Alg, Encoding, Format, KeyType};

/// Turns a PKCS1 private key document into KeyInfo bytes
pub fn pk1_to_rsa_private_key(pk1_doc: &RsaPrivateKeyDocument, encoding: Encoding) -> Result<KeyInfo> {
    let pk1 = pk1_doc.decode();
    let key_length = u32::from(pk1.private_exponent.len()) * 8;
    let key_info = KeyInfo::new()
        .with_alg(Alg::Rsa)
        .with_format(Format::PKCS1)
        .with_key_type(KeyType::Private)
        .with_encoding(encoding)
        .with_key_length(key_length)
        .with_bytes(pk1.to_der()?.as_ref());
    Ok(key_info)
}

/// Turns a PKCS1 public key document into KeyInfo bytes
pub fn pk1_to_rsa_public_key(pk1_doc: &RsaPublicKeyDocument, encoding: Encoding) -> Result<KeyInfo> {
    let pk1 = pk1_doc.decode();
    let key_length = u32::from(pk1.modulus.len()) * 8;
    let key_info = KeyInfo::new()
        .with_alg(Alg::Rsa)
        .with_format(Format::PKCS1)
        .with_key_type(KeyType::Public)
        .with_encoding(encoding)
        .with_key_length(key_length)
        .with_bytes(pk1_doc.as_der());
    Ok(key_info)
}

/// Turn a RSA private key bytes into a PKCS1 document
pub fn rsa_private_key_to_pk1(app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    let bytes = key_info.bytes.clone().unwrap();
    let pkd = RsaPrivateKeyDocument::from_der(&bytes)?;
    match app_state.encoding {
        Encoding::DER => {
            let bytes = pkd.to_der();
            app_state.write_stream(&bytes)?;
        }
        Encoding::PEM => {
            let bytes = pkd.to_pem(CRLF)?;
            app_state.write_stream(bytes.as_bytes())?;
        }
        _ => {}
    }
    Ok(())
}

/// Turn RSA public key bytes into a PKCS1 document
pub fn rsa_public_key_to_pk1(app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    let bytes = key_info.bytes.clone().unwrap();
    let pkd = RsaPublicKeyDocument::from_der(&bytes)?;
    match app_state.encoding {
        Encoding::DER => {
            let bytes = pkd.to_der();
            app_state.write_stream(&bytes)?;
        }
        Encoding::PEM => {
            let bytes = pkd.to_pem(CRLF)?;
            app_state.write_stream(bytes.as_bytes())?;
        }
        _ => {}
    }
    Ok(())
}
