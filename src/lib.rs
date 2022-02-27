//! KT performs very simply key display and conversion functions with 100% Rust code.
//! 
//! KT leverages the [formats](docs.rs/formats) crates from RustCrypto to manage public/private keys in
//! various formats.  To see the full list, run `kt convert --help`
//! 
pub mod alg_id;
pub mod app_state;
pub mod cli;
pub mod conversion;
pub mod discover;
pub mod document;
pub mod errors;
pub mod key_info;
pub mod oids;

