//! Convert between PKCS8 and PKCS1
//!
//! RSA public and private keys can be formated as either raw PKCS1 files or
//! as more standard PKCS8 files.  This utility enables you to quickly check
//! the file type, and to convert between the two types.
//!
//! Note, this only supports RSA keys and any other key should already be in
//! PKCS8 format
//!

use anyhow::Result;
use clap::Parser;
use kt::{app_state::Command, cli::process, convert, discover, show};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[clap(short, long)]
    infile: String,

    /// Number of times to greet
    #[clap(short, long)]
    outfile: String,
    /// Show info about the key
    #[clap(long)]
    show: bool,
}
use clap::{App, Arg};

fn main() -> Result<()> {
    const NAME: &'static str = env!("CARGO_PKG_NAME");
    const VERSION: &'static str = env!("CARGO_PKG_VERSION");
    const DESC: &'static str = env!("CARGO_PKG_DESCRIPTION");

    env_logger::init();

    let args = App::new(NAME)
        .version(VERSION)
        .about(DESC)
        .arg(
            Arg::new("show")
                .long("show")
                .help("Just show deets of input key")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::new("oids")
                .long("oids")
                .help("Dump all the oids")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::new("in")
                .long("in")
                .value_name("FILE")
                .help("Sets the input file to use")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("from")
                .long("from")
                .value_name("PEM|DER|JWK")
                .help("Type of input file")
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
            Arg::new("to")
                .long("to")
                .value_name("PEM|DER|JWK")
                .help("Type of output file")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("kid")
                .long("kid")
                .value_name("NAME")
                .help("Key ID for JWT")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("alg")
                .long("alg")
                .value_name("RSA|EC")
                .help("Key algoritmm")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("inkeytype")
                .long("inkeytype")
                .value_name("PUBLIC|PRIVATE")
                .help("Type of key being input [default is PRIVATE]")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("outkeytype")
                .long("outkeytype")
                .value_name("PUBLIC|PRIVATE")
                .help("Type of key being output [default is PRIVATE")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("informat")
                .long("informat")
                .value_name("PKCS1|PKCS8|SPKI")
                .help("Format of key being input (default is PKCS8)")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("outformat")
                .long("outformat")
                .value_name("PKCS1|PKCS8|SPKI")
                .help("Format of key being output (default is PKCS1)")
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
            Arg::new("outpass")
                .long("outpass")
                .value_name("PASSWORD")
                .help("Password protected ouput")
                .required(false)
                .takes_value(true),
        )
        .get_matches();

    //let fake_args = vec!["kt", "--show" "-i",];
    //let args = app.get_matches_from(fake_args);
    //let args = generate_app().get_matches();
    let mut app_state = process(&args)?;

    match app_state.command {
        Command::Show => {
            let key_info = discover(&mut app_state)?;
            let _key_id = show(&mut app_state, &key_info)?;
        }
        Command::Convert => {
            let key_info = discover(&mut app_state)?;
            convert(&mut app_state, &key_info)?;
        }
        Command::Oids => {
            dump_oids();
        }
    }
    Ok(())
}

fn dump_oid(oid: &[u8]) -> String {
    format!("[u8;{}] = {:?}", oid.len(), oid)
}

fn dump_oids() {
    use kt::oids;

    println!("pub const RSA_ENCRYPTION_BYTES: {};", &dump_oid(oids::RSA_ENCRYPTION.as_bytes()));
    println!("pub const RSASSA_PSS_BYTES: {};", &dump_oid(oids::RSASSA_PSS.as_bytes()));
    println!("pub const ECDSA_BYTES: {};", &dump_oid(oids::ECDSA.as_bytes()));
    println!("pub const PRIME_256_V1_BYTES: {};", &dump_oid(oids::PRIME_256_V1.as_bytes()));

}
