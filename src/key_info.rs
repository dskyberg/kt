use anyhow::Result;
use std::fmt;
use std::str::FromStr;

use pkcs8::der::{Any, Decodable};
use pkcs8::ObjectIdentifier;

use crate::errors::Error;
use crate::oids::oid_to_str;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Unknown,
    Rsa,
    RsaSsaPss,
    Ecdsa,
}

impl Alg {
    pub fn all() -> Vec<&'static str> {
        vec!["RSA", "RSASSA_PSS", "ECDSA"]
    }
}

impl FromStr for Alg {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Alg> {
        match s.to_uppercase().as_str() {
            "RSA" => Ok(Alg::Rsa),
            "RSASSA_PSS" => Ok(Alg::RsaSsaPss),
            "ECDSA" => Ok(Alg::Ecdsa),
            _ => Err(Error::AlgError.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Unknown,
    Public,
    Private,
    KeyPair,
}

impl KeyType {
    pub fn all() -> Vec<&'static str> {
        vec!["PUBLIC", "PRIVATE", "KEYPAIR"]
    }
}

impl FromStr for KeyType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<KeyType> {
        match s.to_uppercase().as_str() {
            "PUBLIC" => Ok(KeyType::Public),
            "PRIVATE" => Ok(KeyType::Private),
            "KEYPAIR" => Ok(KeyType::KeyPair),
            _ => Err(Error::KeyTypeError.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Unknown,
    PKCS1,
    PKCS8,
    SPKI,
    SEC1,
}

impl Format {
    pub fn all() -> Vec<&'static str> {
        vec!["PKCS1", "PKCS8", "SPKI", "SEC1"]
    }
}

impl FromStr for Format {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Format> {
        match s.to_uppercase().as_str() {
            "PKCS8" => Ok(Format::PKCS8),
            "PKCS1" => Ok(Format::PKCS1),
            "SPKI" => Ok(Format::SPKI),
            "SEC1" => Ok(Format::SEC1),
            _ => Ok(Format::Unknown),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Unknown,
    PEM,
    DER,
    JWK,
}

impl Encoding {
    pub fn all() -> Vec<&'static str> {
        vec!["PEM", "DER", "JWK"]
    }
}
impl FromStr for Encoding {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Encoding> {
        match s.to_uppercase().as_str() {
            "PEM" => Ok(Encoding::PEM),
            "DER" => Ok(Encoding::DER),
            "JWK" => Ok(Encoding::JWK),
            _ => Err(Error::EncodingError.into()),
        }
    }
}

#[derive(Clone)]
pub enum Parameter {
    OID(ObjectIdentifier),
    IA5String(String),
}

#[derive(Clone)]
pub struct KeyInfo {
    pub encoding: Encoding,
    pub format: Format,
    pub key_type: KeyType,
    pub key_length: Option<u32>,
    pub alg: Alg,
    pub oid: Option<ObjectIdentifier>,
    pub params: Option<Vec<u8>>,
    pub bytes: Option<Vec<u8>>,
}

impl KeyInfo {
    pub fn new() -> Self {
        Self {
            encoding: Encoding::Unknown,
            format: Format::Unknown,
            key_type: KeyType::Unknown,
            key_length: None,
            alg: Alg::Unknown,
            oid: None,
            params: None,
            bytes: None,
        }
    }
    pub fn encoding(self) -> Encoding {
        self.encoding
    }
    pub fn set_encoding(&mut self, encoding: Encoding) -> &mut Self {
        self.encoding = encoding;
        self
    }
    pub fn with_encoding(mut self, encoding: Encoding) -> Self {
        self.set_encoding(encoding);
        self
    }

    pub fn format(self) -> Format {
        self.format
    }

    pub fn set_format(&mut self, format: Format) -> &mut Self {
        self.format = format;
        self
    }

    pub fn with_format(mut self, format: Format) -> Self {
        self.set_format(format);
        self
    }

    pub fn key_type(self) -> KeyType {
        self.key_type
    }

    pub fn set_key_type(&mut self, key_type: KeyType) -> &mut Self {
        self.key_type = key_type;
        self
    }

    pub fn with_key_type(mut self, key_type: KeyType) -> Self {
        self.set_key_type(key_type);
        self
    }

    pub fn key_length(self) -> Option<u32> {
        self.key_length
    }

    pub fn set_key_length(&mut self, key_length: u32) -> &mut Self {
        if key_length > 0 {
            self.key_length = Some(key_length);
        }
        self
    }

    pub fn with_key_length(mut self, key_length: u32) -> Self {
        self.set_key_length(key_length);
        self
    }

    pub fn alg(self) -> Alg {
        self.alg
    }

    pub fn set_alg(&mut self, alg: Alg) -> &mut Self {
        self.alg = alg;
        self
    }
    pub fn with_alg(mut self, alg: Alg) -> Self {
        self.set_alg(alg);
        self
    }

    pub fn bytes(self) -> Option<Vec<u8>> {
        self.bytes
    }

    pub fn set_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes = Some(bytes.to_vec());
        self
    }

    pub fn with_bytes(mut self, bytes: &[u8]) -> Self {
        self.set_bytes(bytes);
        self
    }

    pub fn oid(self) -> Option<ObjectIdentifier> {
        self.oid
    }

    // For PKCS8 and SPKI formats
    pub fn set_oid(&mut self, oid: &ObjectIdentifier) -> &mut Self {
        self.oid = Some(*oid);
        self
    }

    pub fn with_oid(mut self, oid: &ObjectIdentifier) -> Self {
        self.set_oid(oid);
        self
    }

    pub fn params(self) -> Option<Vec<u8>> {
        self.params
    }
    pub fn set_params(&mut self, params: &[u8]) -> &mut Self {
        self.params = Some(params.to_vec());
        self
    }
    pub fn with_params(mut self, params: &[u8]) -> Self {
        self.set_params(params);
        self
    }
}

impl Default for KeyInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("KeyInfo")
            .field("encoding", &self.encoding)
            .field("format", &self.format)
            .field("key_type", &self.key_type)
            .field("key_length", &self.key_length)
            .field("alg", &self.alg)
            .field("oid", &self.oid)
            .finish()
    }
}
impl fmt::Display for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let key_type = format!("Key Type: {:?}\n", self.key_type);
        let encoding = format!("Encoding: {:?}\n", self.encoding);
        let format = format!("Format: {:?}\n", self.format);
        let alg = format!("Algorithm: {:?}\n", self.alg);

        let key_length = match self.key_length {
            Some(key_length) => format!("Key Length: {:?}\n", key_length),
            None => "".to_owned(),
        };
        let alg_id = alg_id_to_str(self.oid, self.params.as_ref());

        write!(
            f,
            "{}{}{}{}{}{}",
            &key_type, &encoding, &format, &alg, &key_length, &alg_id
        )
    }
}

fn alg_id_to_str(oid: Option<ObjectIdentifier>, params: Option<&Vec<u8>>) -> String {
    match oid {
        Some(oid) => format!(
            "Algorithm Identifier\n\tObject Identifier: {}{}\n",
            oid_to_str(&oid),
            option_any_to_str(params)
        ),
        _ => "".to_owned(),
    }
}

fn option_any_to_str(opt: Option<&Vec<u8>>) -> String {
    let no_val = "".to_owned();
    if let Some(bytes) = opt {
        if let Ok(any) = Any::from_der(bytes) {
            if let Ok(oid) = any.oid() {
                return format!("\n\tParameters: OID {}\n", oid_to_str(&oid));
            }
        } else {
            return "\n\tParameters: Unknown\n".to_string();
        }
    }
    no_val
}
