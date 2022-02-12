use anyhow::Result;
use sec1::der::Document;
use sec1::EcPrivateKeyDocument;

use crate::app_state::{Alg, Encoding, Format, KeyType};
use crate::key_info::KeyInfo;

pub fn sec1_private_key_info(
    sec1_doc: &EcPrivateKeyDocument,
    encoding: Encoding,
) -> Result<KeyInfo> {
    let sec1 = sec1_doc.decode();

    let mut key_info = KeyInfo::new()
        .with_alg(Alg::Ecdsa)
        .with_key_type(KeyType::Private)
        .with_format(Format::SEC1)
        .with_encoding(encoding)
        .with_bytes(sec1_doc.as_der());

    if let Some(params) = sec1.parameters {
        println!("Parameters:       {:?}", &sec1.parameters);
        if let Some(oid) = params.named_curve() {
            key_info.set_oid(&oid);
        }
    }

    Ok(key_info)
}
