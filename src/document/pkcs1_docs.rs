use anyhow::Result;
use pkcs8::der::Document;

use pkcs1::{RsaPrivateKeyDocument, RsaPublicKeyDocument};

use crate::key_info::KeyInfo;
use crate::key_info::{Alg, Encoding, Format, KeyType};

pub fn pk1_to_rsa_private_key(pk1_doc: &RsaPrivateKeyDocument, encoding: Encoding) -> Result<KeyInfo> {
    let pk1 = pk1_doc.decode();
    let key_length = u32::from(pk1.private_exponent.len()) * 8;
    let key_info = KeyInfo::new()
        .with_alg(Alg::Rsa)
        .with_format(Format::PKCS1)
        .with_key_type(KeyType::Private)
        .with_encoding(encoding)
        .with_key_length(key_length)
        .with_bytes(pk1_doc.as_der());
    Ok(key_info)
}
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


