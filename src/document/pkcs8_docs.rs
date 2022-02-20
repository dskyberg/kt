use anyhow::Result;

use log::trace;
use pkcs1::RsaPrivateKeyDocument;
use pkcs8::{
    der::{Document, Encodable},
    EncodePrivateKey,
    EncryptedPrivateKeyDocument,
    LineEnding::CRLF,
    PrivateKeyDocument, PrivateKeyInfo,
};

use crate::app_state::AppState;
use crate::errors::Error;
use crate::key_info::{Alg, Encoding, Format, KeyInfo, KeyType};
use crate::alg_id::rsa_encryption;

pub fn pk8_private_key_info(pk8_doc: &PrivateKeyDocument, encoding: Encoding) -> Result<KeyInfo> {
    let pk8 = pk8_doc.decode();
    let mut key_info = KeyInfo::new()
        .with_key_type(KeyType::Private)
        .with_format(Format::PKCS8)
        .with_encoding(encoding)
        .with_oid(&pk8.algorithm.oid)
        .with_bytes(pk8_doc.as_der());

    if let Some(params) = pk8.algorithm.parameters {
        if let Ok(bytes) = params.to_vec() {
            key_info.set_params(&bytes);
        }
    }

    if let Ok(pk1_doc) = RsaPrivateKeyDocument::from_der(pk8.private_key) {
        let pk1 = pk1_doc.decode();
        let key_length = u32::from(pk1.private_exponent.len()) * 8;
        key_info.set_key_length(key_length);
        key_info.set_alg(Alg::Rsa);
    }

    Ok(key_info)
}

pub fn pk8_encrypted_private_key_info(
    app_state: &AppState,
    enc_pk8_doc: &EncryptedPrivateKeyDocument,
    encoding: Encoding,
) -> Result<KeyInfo> {
    let pwd = app_state.in_password.as_deref();
    if pwd.is_none() {
        return Err(Error::MissingInput("password".to_owned()).into());
    }
    let pk8_doc = enc_pk8_doc.decrypt(pwd.unwrap())?;
    return pk8_private_key_info(&pk8_doc, encoding);
}

/// Turn a PKCS8 PrivateKeyInfo into a document
pub fn pk8_private_key_document(app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    let alg = rsa_encryption()?;
    let bytes = key_info.bytes.clone().unwrap();
    let pki = PrivateKeyInfo::new(alg, &bytes);
    let pkd: PrivateKeyDocument = pki.try_into()?;
    trace!("Created PKCS8 {:?}", &pkd);
    match app_state.encoding {
        Encoding::DER => {
            let bytes = pkd.to_der();
            app_state.write_stream(&bytes)?;
        }
        Encoding::PEM => {
            let bytes = pkd.to_pkcs8_pem(CRLF)?;
            app_state.write_stream(&bytes.as_bytes())?;
        }
        _ => {}
    }
    Ok(())
}
