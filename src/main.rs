//! Perform various common functions on cryptographic keys, such as RSA, ECDSA
//!
//! RSA public and private keys can be formated as either raw PKCS1 files or
//! as more standard PKCS8 files.  This utility enables you to quickly check
//! the file type, and to convert between the two types.
//!
//! Two primary functions are supported - show and convert.  To see the args,
//! ````bash
//! > kt --help
//! ````
//!
use anyhow::Result;
use clap::{Arg, *};
use kt::cli::process;
use kt::key_info::{Alg, Encoding, Format, KeyType};

fn main() -> Result<()> {
    // Grab info from Cargo.toml to show inhelp.
    const NAME: &str = env!("CARGO_PKG_NAME");
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const DESC: &str = env!("CARGO_PKG_DESCRIPTION");

    env_logger::init();

    let args = Command::new(NAME)
        .version(VERSION)
        .about(DESC)
        .subcommand(
            Command::new("show")
                .about("Display info about the provided key")
                .arg(
                    Arg::new("in")
                        .long("in")
                        .short('i')
                        .value_name("FILE")
                        .help("Sets the input file to use")
                        .required(false),
                )
                .arg(
                    Arg::new("inpass")
                        .long("inpass")
                        .value_name("PASSWORD")
                        .help("password for protected input")
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("convert")
                .about("Converts the provided key in the requested manner")
                .arg(
                    Arg::new("in")
                        .long("in")
                        .short('i')
                        .value_name("FILE")
                        .help("Sets the input file to use")
                        .required(false),
                )
                .arg(
                    Arg::new("inpass")
                        .long("inpass")
                        .value_name("PASSWORD")
                        .help("password for protected input")
                        .required(false),
                )
                .arg(
                    Arg::new("out")
                        .long("out")
                        .short('o')
                        .value_name("FILE")
                        .help("Sets the output file to use")
                        .required(false),
                )
                .arg(
                    Arg::new("outpass")
                        .long("outpass")
                        .value_name("PASSWORD")
                        .help("Password protected ouput")
                        .required(false),
                )
                .arg(
                    Arg::new("encoding")
                        .long("encoding")
                        .short('e')
                        .help("Type of output encoding")
                        .required(false)
                        .value_parser(clap::builder::PossibleValuesParser::new(Encoding::all()))
                        .default_value("PEM")
                        .ignore_case(true),
                )
                .arg(
                    Arg::new("kid")
                        .long("kid")
                        .short('k')
                        .help("Key ID for JWT")
                        .required(false),
                )
                .arg(
                    Arg::new("alg")
                        .long("alg")
                        .short('a')
                        .help("Key algoritmm to output")
                        .required(false)
                        .value_parser(clap::builder::PossibleValuesParser::new(Alg::all()))
                        .ignore_case(true),
                )
                .arg(
                    Arg::new("keytype")
                        .long("type")
                        .short('t')
                        .help("Type of key being output")
                        .required(false)
                        .ignore_case(true)
                        .value_parser(clap::builder::PossibleValuesParser::new(KeyType::all()))
                        .ignore_case(true),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .short('f')
                        .value_name("FORMAT")
                        .help("Format of key being output")
                        .required(false)
                        .value_parser(clap::builder::PossibleValuesParser::new(Format::all()))
                        .ignore_case(true),
                ),
        )
        .get_matches();

    process(&args)
}
