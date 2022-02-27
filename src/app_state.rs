//! App State is derived from the command line input arguements
//!
//! AppState contains all the info needed to properly convert the
//! key to the requested format. Note, the input format is derived
//! from the key itself, and represented in [crate::key_info]
//!  
use crate::errors::Error;
use anyhow::Result;
use std::io::{Read, Write};

use crate::key_info::{Alg, Encoding, Format, KeyType};


/// The behavior the app should perform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Display info about the provided key.  Does no conversion
    Show,
    /// Convert the provided key, based on the input parameters
    Convert,
}

/// Program state.
/// Initially established from command line input parameters.
pub struct AppState {
    /// Name of file to read from.  If not provided, stdin is used
    pub in_file: Option<String>,
    /// Name of file to write to.  If not provided stdout is used.
    pub out_file: Option<String>,
    /// Password, if the input fie is encrypted.
    pub in_password: Option<String>,
    /// Password, if the output file should be encrypted.
    pub out_password: Option<String>,
    /// Input stream to read from.  Either a file, or stdin.
    pub in_stream: Box<dyn Read>,
    /// Output stream to write to.  Either a file or stdout.
    pub out_stream: Box<dyn Write>,
    /// If the output is JWT, use this for the KID value
    pub key_id: Option<String>,
    /// Only usable if converting from similar alg, such as to/from
    /// RSA and RSASSA_PSS
    pub alg: Option<Alg>,
    /// Only usable if converting from private to public key
    pub key_type: Option<KeyType>,
    /// Encoding style to output
    pub encoding: Encoding,
    /// File format to use
    pub format: Option<Format>,
    /// Automatically set if an output password is provided
    pub encrypted: bool,
    /// What behavior to perform.  Defaults to "CONVERT"
    pub command: Command,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            key_type: None,
            encoding: Encoding::PEM,
            format: None,
            key_id: None,
            alg: None,
            in_file: None,
            in_password: None,
            in_stream: Box::new(std::io::stdin()),
            out_file: None,
            out_password: None,
            out_stream: Box::new(std::io::stdout()),
            encrypted: false,
            command: Command::Convert,
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}


impl AppState {
    /// Reads the input either from file or stdin
    /// If an input filename is provided on the command line, it will be
    /// read.  If no filename is provided, stdin will be used.
    pub fn read_stream(&mut self) -> Result<Vec<u8>> {
        let mut bytes = Vec::<u8>::new();
        let _cnt = self
            .in_stream
            .read_to_end(&mut bytes)
            .map_err(Error::IOEReadError);
        Ok(bytes)
    }

    /// Writes the output either to file or stdout
    /// If an output filename is provided on the command line, it will be
    /// written.  If no filename is provided, stdout will be used.
    pub fn write_stream(&mut self, bytes: &[u8]) -> Result<()> {
        let _ = self
            .out_stream
            .write_all(bytes)
            .map_err(Error::IOEWriteError);
        Ok(())
    }

    /// Return the alg or Error::MissingAlg
    pub fn alg(&self) -> Result<Alg> {
        self.alg.ok_or_else(||Error::MissingAlg.into())
    }

    /// Return the encoding or Error::MissingEncoding. For consistency. Since encoding
    /// is not an Option, it will always return Ok.
    pub fn encoding(self) -> Result<Encoding> {
        Ok(self.encoding)
    }

    // Return the format or Error::MissingFormat
    pub fn format(self) -> Result<Format> {
        self.format.ok_or_else(||Error::MissingFormat.into())
    }

}
