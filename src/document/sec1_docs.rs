use anyhow::Result;
use sec1::{der::Document, LineEnding::CRLF};
use sec1::EcPrivateKeyDocument;

use crate::app_state::AppState;
use crate::key_info::KeyInfo;
use crate::key_info::{Alg, Encoding, Format, KeyType};

pub fn sec1_to_private_key_info(
    sec1_doc: &EcPrivateKeyDocument,
    encoding: Encoding,
) -> Result<KeyInfo> {
    println!("Doing SECG");
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

/// Turn a PrivateKeyInfo into a SECG document
pub fn private_key_info_to_sec1(app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {

    let bytes = key_info.bytes.clone().unwrap();
    let pkd = EcPrivateKeyDocument::from_der(&bytes)?;
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
