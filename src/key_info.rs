//! Key metadata struct and supporting methods.
//! 
//! The KeyInfo methods supports chained style construction:
//! ```
//! use kt::key_info::{KeyInfo, Alg};
//! let alg = Alg::Rsa;
//! let key_info = KeyInfo::new().with_alg(alg);
//! println!("Key info\n{:}", key_info);
//! ```
//! 
use anyhow::Result;
use core::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use pkcs8::der::{Any, Decodable};
use pkcs8::{AlgorithmIdentifier, ObjectIdentifier};
use zeroize::Zeroizing;

use crate::alg_id::alg_params;
use crate::errors::Error;
use crate::oids;
use crate::oids::oid_to_str;

/// Supported key algorithms
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Unknown,
    Rsa,
    RsaSsaPss,
    Ecdsa,
    X25519,
    X448,
    EdDsa25519,
    EdDsa448,
    EdDsa25519Ph,
    EdDsa448Ph,
}

impl Alg {
    pub fn all() -> Vec<&'static str> {
        vec![
            "RSA",
            "RSASSA_PSS",
            "ECDSA",
            "X25519",
            "X448",
            "EDDSA448",
            "ED_DSA448",
            "EDDSA448PH",
            "ED_DSA448_PH",
            "EDDSA25519PH",
            "ED_DSA25519_PH",
        ]
    }
}

impl TryFrom<&ObjectIdentifier> for Alg {
    type Error = anyhow::Error;
    fn try_from(oid: &ObjectIdentifier) -> Result<Alg> {
        match *oid {
            oids::RSA_ENCRYPTION => Ok(Self::Rsa),
            oids::RSASSA_PSS => Ok(Self::Rsa),
            oids::ECDSA => Ok(Self::Ecdsa),
            oids::X25519 => Ok(Self::X25519),
            oids::X448 => Ok(Self::X448),
            oids::ED_DSA25519 => Ok(Self::EdDsa25519),
            oids::ED_DSA448 => Ok(Self::EdDsa448),
            oids::ED_DSA25519_PH => Ok(Self::EdDsa25519Ph),
            oids::ED_DSA448_PH => Ok(Self::EdDsa448Ph),
            _ => Err(Error::UnknownAlg.into()),
        }
    }
}

impl FromStr for Alg {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Alg> {
        match s.to_uppercase().as_str() {
            "RSA" => Ok(Alg::Rsa),
            "RSASSA_PSS" => Ok(Alg::RsaSsaPss),
            "ECDSA" => Ok(Alg::Ecdsa),
            "X25519" => Ok(Alg::X25519),
            "X448" => Ok(Alg::X448),
            "EDDSA448" | "ED_DSA448" => Ok(Alg::EdDsa448),
            "EDDSA25519" | "ED_DSA25519" => Ok(Alg::EdDsa25519),
            "EDDSA448PH" | "ED_DSA448_PH" => Ok(Alg::EdDsa448Ph),
            "EDDSA25519PH" | "ED_DSA25519_PH" => Ok(Alg::EdDsa25519Ph),
            _ => Err(Error::UnknownAlg.into()),
        }
    }
}

impl fmt::Display for Alg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let txt = match self {
            Alg::Unknown => "Unknown",
            Alg::Rsa => "rsaEncryption",
            Alg::RsaSsaPss => "rsassaPss",
            Alg::Ecdsa => "id-ecPublicKey",
            Alg::X25519 => "id-X25519",
            Alg::X448 => "id-X448",
            Alg::EdDsa25519 => "id-EdDSA25519",
            Alg::EdDsa448 => "id-EdDSA448",
            Alg::EdDsa25519Ph => "id-EdDSA25519-ph",
            Alg::EdDsa448Ph => "id-EdDSA448-ph",
        };

        write!(f, "{}", txt)
    }
}

/// Supported key types, such as Private and Public
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
            _ => Err(Error::UnknownKeyType.into()),
        }
    }
}

/// Supported document formats, such as PKCS8
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

/// Supported file encodings, such as PEM and DER
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
            _ => Err(Error::UnknownEncoding.into()),
        }
    }
}

/// Metadata associated with the input key
#[derive(Clone)]
pub struct KeyInfo {
    /// File encoding type, such as PEM or DER
    pub encoding: Encoding,
    /// Document format, such as PKCS8, PKCS1, SECG, etc.
    pub format: Format,
    /// Public or private
    pub key_type: KeyType,
    /// Length in bits - such as 2048
    pub key_length: Option<u32>,
    /// Key algorithm.  Such as RSA or ECDSA
    pub alg: Alg,
    /// For PKCS8, SPKI, the doc OID
    pub oid: Option<ObjectIdentifier>,
    /// Potential parameters associated with AlgorithmIdentifiers, such as ECDSA curves.
    pub params: Option<Vec<u8>>,
    /// Actual key bytes from the input document
    /// 
    /// The inner key bytes from the formatted document. Not the entire doc.  
    /// Although Zeroize is used (to zeroize on drop), security has not been verified!
    pub bytes: Option<Zeroizing<Vec<u8>>>,
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

    /// Mutable variant to set encoding
    pub fn set_encoding(&mut self, encoding: Encoding) -> &mut Self {
        self.encoding = encoding;
        self
    }
    /// Chainable variant to set encoding
    pub fn with_encoding(mut self, encoding: Encoding) -> Self {
        self.set_encoding(encoding);
        self
    }
    /// Mutable variant to set the format
    pub fn set_format(&mut self, format: Format) -> &mut Self {
        self.format = format;
        self
    }

    /// Chainable variant to set the format
    pub fn with_format(mut self, format: Format) -> Self {
        self.set_format(format);
        self
    }

    /// Mutable variant to set the key_type
    pub fn set_key_type(&mut self, key_type: KeyType) -> &mut Self {
        self.key_type = key_type;
        self
    }

    /// Chainable variant to set the key_type
    pub fn with_key_type(mut self, key_type: KeyType) -> Self {
        self.set_key_type(key_type);
        self
    }

    /// Mutable variant to set the key_length
    pub fn set_key_length(&mut self, key_length: u32) -> &mut Self {
        if key_length > 0 {
            self.key_length = Some(key_length);
        }
        self
    }

    /// Chainable variant to set the key_length
    pub fn with_key_length(mut self, key_length: u32) -> Self {
        self.set_key_length(key_length);
        self
    }

    /// Mutable variant to set the alg
    pub fn set_alg(&mut self, alg: Alg) -> &mut Self {
        self.alg = alg;
        self
    }

    /// Chainable variant to set the alg
    pub fn with_alg(mut self, alg: Alg) -> Self {
        self.set_alg(alg);
        self
    }

    /// Mutable variant to set the key bytes
    pub fn set_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes = Some(Zeroizing::new(bytes.to_vec()));
        self
    }

    /// Chainable variant to set the key bytes
    pub fn with_bytes(mut self, bytes: &[u8]) -> Self {
        self.set_bytes(bytes);
        self
    }

    // Mutable variant to set the oid from PKCS8 and SPKI formats
    pub fn set_oid(&mut self, oid: &ObjectIdentifier) -> &mut Self {
        self.oid = Some(*oid);
        self
    }

    /// Chainable vaiant to set the oid
    pub fn with_oid(mut self, oid: &ObjectIdentifier) -> Self {
        self.set_oid(oid);
        self
    }

    /// Mutable variant to set the params from an AlgorithmIdentifier
    pub fn set_params(&mut self, params: &[u8]) -> &mut Self {
        self.params = Some(params.to_vec());
        self
    }

    /// Chainable variant to set th params
    pub fn with_params(mut self, params: &[u8]) -> Self {
        self.set_params(params);
        self
    }

    /// Chainable variant to set the alg, oid, and params 
    /// from an AlgorithmIdentifier
    pub fn with_alg_id(mut self, alg_id: &AlgorithmIdentifier) -> Self {
        if let Ok(alg) = Alg::try_from(&alg_id.oid) {
            self.set_alg(alg);
        }
        self.set_oid(&alg_id.oid);
        self.params = alg_params(alg_id);
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

/// This method is the basis for the "show" command on the CLI.
impl fmt::Display for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let key_type = format!("Key Type: {:?}\n", self.key_type);
        let encoding = format!("Encoding: {:?}\n", self.encoding);
        let format = format!("Format: {:?}\n", self.format);
        let alg = format!("Algorithm: {}\n", self.alg);

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
