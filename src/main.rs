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
use kt::behavior::{convert::convert, discover::discover, oids::oids, show::show};
use kt::key_info::{Alg, Encoding, Format, KeyType};
use kt::{app_state::Mode, cli::process};

fn main() -> Result<()> {
    // Grab info from Cargo.toml to show inhelp.
    const NAME: &str = env!("CARGO_PKG_NAME");
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const DESC: &str = env!("CARGO_PKG_DESCRIPTION");

    env_logger::init();

    let args = Command::new(NAME)
        .version(VERSION)
        .about(DESC)
        .subcommand(Command::new("oids").about("Display some ObjectIdentifiers for Rust dev"))
        .subcommand(
            Command::new("show")
                .about("Display info about the provided key")
                .arg(
                    Arg::new("in")
                        .long("in")
                        .value_name("FILE")
                        .help("Sets the input file to use")
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("inpass")
                        .long("inpass")
                        .value_name("PASSWORD")
                        .help("password for protected input")
                        .required(false)
                        .takes_value(true),
                ),
        )
        .subcommand(
            Command::new("convert")
                .about("Converts the provided key in the requested manner")
                .arg(
                    Arg::new("in")
                        .long("in")
                        .value_name("FILE")
                        .help("Sets the input file to use")
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("inpass")
                        .long("inpass")
                        .value_name("PASSWORD")
                        .help("password for protected input")
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("out")
                        .long("out")
                        .value_name("FILE")
                        .help("Sets the output file to use")
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("outpass")
                        .long("outpass")
                        .value_name("PASSWORD")
                        .help("Password protected ouput")
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("encoding")
                        .long("encoding")
                        .short('e')
                        .help("Type of output encoding")
                        .required(false)
                        .takes_value(true)
                        .possible_values(Encoding::all())
                        .default_value("PEM"),
                )
                .arg(
                    Arg::new("kid")
                        .long("kid")
                        .short('k')
                        .help("Key ID for JWT")
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("alg")
                        .long("alg")
                        .short('a')
                        .help("Key algoritmm to output")
                        .required(false)
                        .takes_value(true)
                        .possible_values(Alg::all()),
                )
                .arg(
                    Arg::new("keytype")
                        .long("type")
                        .short('t')
                        .help("Type of key being output")
                        .required(false)
                        .takes_value(true)
                        .ignore_case(true)
                        .possible_values(KeyType::all()),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .short('f')
                        .value_name("FORMAT")
                        .help("Format of key being output")
                        .required(false)
                        .takes_value(true)
                        .possible_values(Format::all())
                ),
        )
        .get_matches();

    let mut app_state = process(&args)?;

    match app_state.mode {
        Mode::Show => {
            let key_info = discover(&mut app_state)?;
            let _key_id = show(&mut app_state, &key_info)?;
        }
        Mode::Convert => {
            let key_info = discover(&mut app_state)?;
            convert(&mut app_state, &key_info)?;
        }
        Mode::Oids => {
            oids();
        }
    }
    Ok(())
}
