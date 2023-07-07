//! Command Line Interface
//!
//! Processes the command line args to create an [AppState] instance, and then runs the
//! requested sub command.
//!
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

use anyhow::{bail, Result};
use clap::ArgMatches;

use crate::app_state::*;
use crate::conversion::convert;
use crate::discover::discover;
use crate::errors::Error;
use crate::key_info::{Alg, Encoding, Format, KeyType};

/// Read a password from a local file
///
/// If the arg to `process_password` is `FILE:<filename>` this method is called
/// to retrieve the password from `<filename>`.
fn read_password_from_file(filename: &str) -> Result<Option<String>> {
    let mut file = File::open(filename).map_err(Error::ReadFileError)?;
    let mut buf = String::new();
    let _cnt = file.read_to_string(&mut buf).map_err(Error::IOEReadError);

    Ok(Some(buf))
}

/// Handle password input options similar to openssl
///
/// The password may be of 2 forms:
/// 1. "pass:<value>": The value after the colon represents the actual password
/// 2. "file:<value>": The value after the colon represents a file that contains the password
///
fn process_password(input: Option<&str>) -> Result<Option<String>> {
    match input {
        None => Ok(None),
        Some(s) => {
            let parts = s.split(':').collect::<Vec<&str>>();
            // If there's not enough args, bail
            if parts.len() < 2 {
                bail!(Error::BadPasswordArg);
            }
            let mode = parts[0].to_owned();
            let target;

            // If the password contains a ':', join them
            if parts.len() > 2 {
                match parts.split_first() {
                    Some((_, remainder)) => {
                        target = remainder.join("");
                    }
                    _ => bail!(Error::BadPasswordArg),
                }
            } else {
                target = parts[1].to_owned();
            }
            match mode.to_lowercase().as_str() {
                "pass" => Ok(Some(target)),
                "file" => read_password_from_file(&target),
                _ => bail!(Error::BadPasswordArg),
            }
        }
    }
}

/// Processes all CLI arguments into an instance of AppState
pub fn process(matches: &ArgMatches) -> Result<()> {
    let mut app_state: AppState = Default::default();

    // Process the top level inputs

    // Open the input reader.  Bail on error

    match matches.subcommand() {
        Some(("show", matches)) => {
            app_state.command = Command::Show;
            if let Some(filename) = matches.get_one::<String>("in") {
                app_state.in_file = Some(filename.to_string());
                app_state.in_stream =
                    Box::new(std::fs::File::open(filename).map_err(Error::ReadFileError)?);
                //TODO IF no from arg is provided, see if we can determine from the filename.
                if !matches.contains_id("in") {}
            }
            app_state.in_password =
                process_password(matches.get_one::<String>("inpass").map(|s| s.as_str()))?;
        }

        Some(("convert", matches)) => {
            app_state.command = Command::Convert;
            if let Some(filename) = matches.get_one::<String>("in") {
                app_state.in_file = Some(filename.to_string());
                app_state.in_stream =
                    Box::new(std::fs::File::open(filename).map_err(Error::ReadFileError)?);
                //TODO IF no from arg is provided, see if we can determine from the filename.
                if !matches.contains_id("in") {}
            }

            app_state.in_password =
                process_password(matches.get_one::<String>("inpass").map(|s| s.as_str()))?;

            // Open the output writer.  Bail on error
            if let Some(filename) = matches.get_one::<String>("out") {
                app_state.out_file = Some(filename.to_string());
                app_state.out_stream =
                    Box::new(std::fs::File::create(filename).map_err(Error::ReadFileError)?);
                //TODO IF no from arg is provided, see if we can determine from the filename.
                if !matches.contains_id("in") {}
            }

            app_state.out_password =
                process_password(matches.get_one::<String>("outpass").map(|s| s.as_str()))?;

            if let Some(format) = matches.get_one::<String>("format") {
                app_state.format = Some(Format::from_str(format)?);
            }

            if let Some(encoding) = matches.get_one::<String>("encoding") {
                app_state.encoding = Encoding::from_str(encoding)?;
            }

            if let Some(keytype) = matches.get_one::<String>("keytype") {
                app_state.key_type = Some(KeyType::from_str(keytype)?);
            }

            if let Some(alg) = matches.get_one::<String>("alg") {
                app_state.alg = Some(Alg::from_str(alg)?);
            }

            if let Some(kid) = matches.get_one::<String>("kid") {
                app_state.key_id = Some(kid.to_owned());
            }
        }
        _ => {}
    };

    match app_state.command {
        Command::Show => {
            let key_info = discover(&mut app_state)?;
            println!("{:}", key_info);
        }
        Command::Convert => {
            let key_info = discover(&mut app_state)?;
            convert(&mut app_state, &key_info)?;
        }
    }
    Ok(())
}
