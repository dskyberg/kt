use anyhow::Result;
use spki::{
    der::{Document, Encodable},
    PublicKeyDocument,
};

use pkcs1::RsaPublicKeyDocument;

use crate::app_state::{Alg, Encoding, Format, KeyType};
use crate::key_info::KeyInfo;

pub fn spki_public_key_info(spki_doc: &PublicKeyDocument, encoding: Encoding) -> Result<KeyInfo> {
    let spki = spki_doc.decode();
    let mut key_info = KeyInfo::new()
        .with_key_type(KeyType::Public)
        .with_format(Format::SPKI)
        .with_encoding(encoding)
        .with_oid(&spki.algorithm.oid)
        .with_bytes(spki_doc.as_der());

    println!("AlgorithmID:       {:?}", &spki.algorithm);

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
