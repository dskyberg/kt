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

    /// Represents unknown file type error`.
    #[error("Uknown file type")]
    FileTypeError,

    /// Represents unknown file type error`.
    #[error("Uknown file type")]
    EncodingError,

    /// Represents unknown file type error`.
    #[error("Uknown algorithm")]
    AlgError,

    /// Represents unknown file type error`.
    #[error("Uknown key type")]
    KeyTypeError,

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

    #[error("unknown key type")]
    UnknownKeyType,
}
