//! Enumerates all possible errors returned by this library.
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    /// Represents a failure to read from input.
    #[error("File input error")]
    ReadFileError(std::io::Error),

    /// Represents a failure to write to output.
    #[error("File output error")]
    WriteFileError(std::io::Error),

    /// Represents all other cases of `std::io::Error` when reading.
    #[error("Stream read error")]
    IOEReadError(std::io::Error),

    /// Represents all other cases of `std::io::Error` when writing.
    #[error("Stream write error")]
    IOEWriteError(std::io::Error),

    #[error("Bad PKCS8 file")]
    BadPKCS8File(#[from] pkcs8::Error),

    #[error("Bad PKCS8 DER")]
    BadPKCS8DER(pkcs8::der::Error),

    /// Represents a missing algorithm`.
    #[error("No algorithm was provided")]
    MissingAlg,
    
    /// Represents unknown or unsupported algorithm`.
    #[error("Uknown or unsupported algorithm")]
    UnknownAlg,
    
    /// Represents a missing file format`.
    #[error("No format was provided")]
    MissingFormat,

    /// Represents unknown or unsupported file format`.
    #[error("Uknown or unsupported format")]
    UnknownFormat,

    /// Represents a missing encoding`.
    #[error("No encoding was provided")]
    MissingEncoding,

    /// Represents unknown or unsupported encoding`.
    #[error("Uknown or unsupported encoding")]
    UnknownEncoding,

    /// Represents unknown or unsupported key type`.
    #[error("Uknown key type")]
    UnknownKeyType,

    #[error("Input type mismatch")]
    TypeMismatch,

    #[error("Option is not yet supported")]
    NotSupported,

    #[error("Badly formed password arguement")]
    BadPasswordArg,

    #[error("Bad crypto error")]
    BadCrypto,

    #[error("Missing input: {0}")]
    MissingInput(String),
}
