use anyhow::{bail, Result};

use pkcs1::RsaPrivateKeyDocument;
use pkcs8::{
    der::Document,
    EncodePrivateKey, EncryptedPrivateKeyDocument,
    LineEnding::CRLF,
    PrivateKeyDocument, PrivateKeyInfo,
};

use crate::alg_id::{rsa_encryption, rsapss_encryption};
use crate::app_state::AppState;
use crate::errors::Error;
use crate::key_info::{Alg, Encoding, Format, KeyInfo, KeyType};

/// Convert a PKCS8 private key document into KeyInfo bytes
pub fn pk8_to_private_key_info(
    pk8_doc: &PrivateKeyDocument,
    encoding: Encoding,
) -> Result<KeyInfo> {
    let pk8 = pk8_doc.decode();
    let mut key_info = KeyInfo::new()
        .with_key_type(KeyType::Private)
        .with_format(Format::PKCS8)
        .with_encoding(encoding)
        .with_alg_id(&pk8.algorithm)
        .with_bytes(pk8_doc.as_der());

    if let Ok(pk1_doc) = RsaPrivateKeyDocument::from_der(pk8.private_key) {
        let pk1 = pk1_doc.decode();
        let key_length = u32::from(pk1.private_exponent.len()) * 8;
        key_info.set_key_length(key_length);
        key_info.set_alg(Alg::Rsa);
    }

    Ok(key_info)
}

/// Convert an encrypted PKCS8 private key document into KeyInfo bytes
pub fn pk8_encrypted_to_private_key_info(
    app_state: &AppState,
    enc_pk8_doc: &EncryptedPrivateKeyDocument,
    encoding: Encoding,
) -> Result<KeyInfo> {
    let pwd = app_state.in_password.as_deref();
    if pwd.is_none() {
        return Err(Error::MissingInput("password".to_owned()).into());
    }
    let pk8_doc = enc_pk8_doc.decrypt(pwd.unwrap())?;
    pk8_to_private_key_info(&pk8_doc, encoding)
}

/// Turn a PKCS8 PrivateKeyInfo into a document
pub fn private_key_info_to_pk8(app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    let alg_id = match app_state.alg()? {
        Alg::Rsa => rsa_encryption()?,
        Alg::RsaSsaPss => rsapss_encryption()?,
        _ => bail!(Error::UnknownAlg),
    };

    let bytes = key_info.bytes.clone().unwrap();
    let pki = PrivateKeyInfo::new(alg_id, &bytes);
    let pkd: PrivateKeyDocument = pki.try_into()?;
    match app_state.encoding {
        Encoding::DER => {
            let bytes = pkd.to_der();
            app_state.write_stream(&bytes)?;
        }
        Encoding::PEM => {
            let bytes = pkd.to_pkcs8_pem(CRLF)?;
            app_state.write_stream(bytes.as_bytes())?;
        }
        _ => {}
    }
    Ok(())
}
