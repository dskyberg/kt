use crate::app_state::{Alg, Encoding, Format, KeyType};
use crate::oids::oid_to_str;
use pkcs8::der::{Any, Decodable};
use pkcs8::ObjectIdentifier;
use std::fmt;

#[derive(Clone)]
pub enum Parameter {
    OID(ObjectIdentifier),
    IA5String(String),
}

#[derive(Clone)]
pub struct KeyInfo {
    encoding: Option<Encoding>,
    format: Option<Format>,
    key_type: Option<KeyType>,
    key_length: Option<u32>,
    alg: Option<Alg>,
    oid: Option<ObjectIdentifier>,
    params: Option<Vec<u8>>,
    bytes: Option<Vec<u8>>,
}

impl KeyInfo {
    pub fn new() -> Self {
        Self {
            encoding: None,
            format: None,
            key_type: None,
            key_length: None,
            alg: None,
            oid: None,
            params: None,
            bytes: None,
        }
    }
    pub fn encoding(self) -> Option<Encoding> {
        self.encoding
    }
    pub fn set_encoding(&mut self, encoding: Encoding) -> &mut Self {
        self.encoding = Some(encoding);
        self
    }
    pub fn with_encoding(mut self, encoding: Encoding) -> Self {
        self.set_encoding(encoding);
        self
    }

    pub fn set_format(&mut self, format: Format) -> &mut Self {
        self.format = Some(format);
        self
    }

    pub fn with_format(mut self, format: Format) -> Self {
        self.set_format(format);
        self
    }
    pub fn key_type(self) -> Option<KeyType> {
        self.key_type
    }

    pub fn set_key_type(&mut self, key_type: KeyType) -> &mut Self {
        self.key_type = Some(key_type);
        self
    }
    pub fn with_key_type(mut self, key_type: KeyType) -> Self {
        self.set_key_type(key_type);
        self
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
    pub fn set_alg(&mut self, alg: Alg) -> &mut Self {
        self.alg = Some(alg);
        self
    }
    pub fn with_alg(mut self, alg: Alg) -> Self {
        self.set_alg(alg);
        self
    }
    pub fn set_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes = Some(bytes.to_vec().clone());
        self
    }
    pub fn with_bytes(mut self, bytes: &[u8]) -> Self {
        self.set_bytes(bytes);
        self
    }
    // For PKCS8 and SPKI formats
    pub fn set_oid(&mut self, oid: &ObjectIdentifier) -> &mut Self {
        self.oid = Some(oid.clone());
        self
    }
    pub fn with_oid(mut self, oid: &ObjectIdentifier) -> Self {
        self.set_oid(oid);
        self
    }
    pub fn params(self) -> Option<Vec<u8>> {
        match self.params {
            Some(value) => Some(value.clone()),
            None => None,
        }
    }
    pub fn set_params(&mut self, params: &[u8]) -> &mut Self {
        self.params = Some(params.to_vec().clone());
        self
    }
    pub fn with_params(mut self, params: &[u8]) -> Self {
        self.set_params(params);
        self
    }
}

/*
encoding: None,
format: None,
key_type: None,
key_length: None,
alg: None,
bytes: None
*/

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
        let key_type = match self.key_type {
            Some(key_type) => format!("Key Type: {:?}\n", key_type),
            None => "".to_owned(),
        };
        let encoding = match self.encoding {
            Some(encoding) => format!("Encoding: {:?}\n", encoding),
            None => "".to_owned(),
        };
        let format = match self.format {
            Some(format) => format!("Format: {:?}\n", format),
            None => "".to_owned(),
        };
        let alg = match self.alg {
            Some(alg) => format!("Algorithm: {:?}\n", alg),
            None => "".to_owned(),
        };
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
        if let Ok(any) = Any::from_der(&bytes) {
            if let Ok(oid) = any.oid() {
                return format!("\n\tParameters: OID {}\n", oid_to_str(&oid));
            }
        } else {
            return format!("\n\tParameters: Unknown\n");
        }
    }
    no_val
}
