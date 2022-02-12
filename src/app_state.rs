//! App State is derived from the command line input arguements
//!
use crate::errors::Error;
use anyhow::{bail, Result};
use std::io::{Read, Write};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Rsa,
    RsaSsaPss,
    Ecdsa,
}

impl FromStr for Alg {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Alg> {
        match s.to_uppercase().as_str() {
            "RSA" => Ok(Alg::Rsa),
            "RSASSA_PSS" => Ok(Alg::RsaSsaPss),
            "ECDSA" => Ok(Alg::Ecdsa),
            _ => bail!(Error::AlgError),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Public,
    Private,
    KeyPair,
}

impl FromStr for KeyType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<KeyType> {
        match s.to_uppercase().as_str() {
            "PUBLIC" => Ok(KeyType::Public),
            "PRIVATE" => Ok(KeyType::Private),
            "KEYPAIR" => Ok(KeyType::KeyPair),
            _ => bail!(Error::KeyTypeError),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    PKCS1,
    PKCS8,
    SPKI,
    SEC1,
    Unknown,
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
    PEM,
    DER,
    JWK,
}

impl FromStr for Encoding {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Encoding> {
        match s.to_uppercase().as_str() {
            "PEM" => Ok(Encoding::PEM),
            "DER" => Ok(Encoding::DER),
            "JWK" => Ok(Encoding::JWK),
            _ => bail!(Error::EncodingError),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Show,
    Convert,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Params {
    pub key_type: KeyType,
    pub file: Option<String>,
    pub encoding: Encoding,
    pub format: Format,
    pub encrypted: bool,
    pub password: Option<String>,
}

pub struct AppState {
    pub in_params: Params,
    pub out_params: Params,
    pub in_stream: Box<dyn Read>,
    pub out_stream: Box<dyn Write>,
    pub key_id: Option<String>,
    pub alg: Alg,
    pub command: Command,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            in_params: Params {
                key_type: KeyType::Private,
                file: None,
                encoding: Encoding::PEM,
                format: Format::PKCS8,
                encrypted: false,
                password: None,
            },
            out_params: Params {
                key_type: KeyType::Private,
                file: None,
                encoding: Encoding::PEM,
                format: Format::PKCS1,
                encrypted: false,
                password: None,
            },
            in_stream: Box::new(std::io::stdin()),
            out_stream: Box::new(std::io::stdout()),
            key_id: None,
            alg: Alg::Rsa,
            command: Command::Convert,
        }
    }
}

impl AppState {
    pub fn read_stream(&mut self) -> Result<Vec<u8>> {
        let mut bytes = Vec::<u8>::new();
        let _cnt = self
            .in_stream
            .read_to_end(&mut bytes)
            .map_err(|e| Error::IOEReadError(e));
        Ok(bytes)
    }

    pub fn write_stream(&mut self, bytes: &[u8]) -> Result<()> {
        let _ = self
            .out_stream
            .write_all(bytes)
            .map_err(|e| Error::IOEWriteError(e));
        Ok(())
    }
}
