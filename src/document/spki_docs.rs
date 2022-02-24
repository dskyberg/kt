use anyhow::Result;
use log::trace;

use pkcs8::{SubjectPublicKeyInfo, LineEnding::CRLF};
use spki::{
    der::{Document, Encodable},
    PublicKeyDocument,
};
use pkcs1::RsaPublicKeyDocument;

use crate::alg_id::rsa_encryption;
use crate::app_state::AppState;
use crate::key_info::KeyInfo;
use crate::key_info::{Alg, Encoding, Format, KeyType};

pub fn spki_public_key_info(spki_doc: &PublicKeyDocument, encoding: Encoding) -> Result<KeyInfo> {
    let spki = spki_doc.decode();
    let mut key_info = KeyInfo::new()
        .with_key_type(KeyType::Public)
        .with_format(Format::SPKI)
        .with_encoding(encoding)
        .with_oid(&spki.algorithm.oid)
        //.with_bytes(spki_doc.as_der());
        .with_bytes(spki.subject_public_key);

    if let Some(params) = spki.algorithm.parameters {
        if let Ok(bytes) = params.to_vec() {
            key_info.set_params(&bytes);
        }
    }

    if let Ok(pk1_doc) = RsaPublicKeyDocument::from_der(spki.subject_public_key) {
        let pk1 = pk1_doc.decode();
        let key_length = u32::from(pk1.modulus.len()) * 8;
        key_info.set_key_length(key_length);
        key_info.set_alg(Alg::Rsa);
    }

    Ok(key_info)
}

// pub fn spki_public_key_document(spki: &SubjectPublicKeyInfo)
/// Turn a PKCS8 PrivateKeyInfo into a document
pub fn spki_public_key_document(app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    let alg = rsa_encryption()?;
    let bytes = key_info.bytes.clone().unwrap();

    let spki = SubjectPublicKeyInfo{
        algorithm: alg,
        subject_public_key: &bytes
    };
    let pkd: PublicKeyDocument = spki.try_into()?;
    trace!("Created SPKI {:?}", &pkd);
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
