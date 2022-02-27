//! Convert the format or encoding of the input file
//! 
//! The requested conversion is represented by the command line args
//! captured in [AppState]. The source key is represented in [KeyInfo], which
//! is determined by the [discover](crate::discover) functionality.
use anyhow::Result;
use log::{debug, info, trace};

use crate::app_state::AppState;
use crate::document::{
    pkcs1_docs::{rsa_private_key_to_pk1, rsa_public_key_to_pk1},
    pkcs8_docs::private_key_info_to_pk8,
    sec1_docs::private_key_info_to_sec1,
    spki_docs::key_info_to_spki,
};
use crate::errors::Error;
use crate::key_info::KeyInfo;
use crate::key_info::{Alg, Format, KeyType};

fn convert_rsa_private(app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    let format = app_state.format.ok_or(Error::MissingFormat)?;
    match format {
        Format::PKCS1 => Ok(rsa_private_key_to_pk1(app_state, key_info)?),
        Format::PKCS8 => Ok(private_key_info_to_pk8(app_state, key_info)?),
        _ => {
            trace!("Unsupported format: {:?}", format);
            Err(Error::NotSupported.into())
        }
    }
}

fn convert_rsa_public(app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    let format = app_state.format.ok_or(Error::MissingFormat)?;
    match format {
        Format::PKCS1 => Ok(rsa_public_key_to_pk1(app_state, key_info)?),
        Format::PKCS8 | Format::SPKI => Ok(key_info_to_spki(app_state, key_info)?),
        _ => {
            trace!("Unsupported format: {:?}", format);
            Err(Error::NotSupported.into())
        }
    }
}

// Make sure the type of key provided can be converted to the type of key
// requested
fn verify_key_types(ki_type: KeyType, as_type: KeyType) -> Result<()> {
    if ki_type == KeyType::Public && as_type != KeyType::Public {
        info!("Cannot convert from public key to private key");
        return Err(Error::TypeMismatch.into());
    }
    Ok(())
}


fn safe_to_convert<'a>(
    app_state: &'a mut AppState,
    key_info: &'a KeyInfo,
) -> Result<(&'a mut AppState, &'a KeyInfo)> {
    let kt = key_info.key_type;
    let as_type = app_state.key_type.unwrap_or(KeyType::Unknown);
    // Make sure we aren't trying to convert public keys into private keys
    verify_key_types(kt, as_type)?;

    Ok((app_state, key_info))
}

fn convert_key(params: (&mut AppState, &KeyInfo)) -> Result<()> {
    let app_state = params.0;
    let key_info = params.1;
    match (key_info.alg, key_info.key_type) {
        (Alg::Rsa | Alg::RsaSsaPss, KeyType::Private) => convert_rsa_private(app_state, key_info),
        (Alg::Rsa | Alg::RsaSsaPss, KeyType::Public) => convert_rsa_public(app_state, key_info),
        (Alg::EdDsa25519 | Alg::Ecdsa, KeyType::Private) => private_key_info_to_sec1(app_state, key_info),
        (Alg::EdDsa25519 | Alg::Ecdsa, KeyType::Public) => key_info_to_spki(app_state, key_info),

        (a, b) => {
            debug!("{:?} - {:?}", &a, &b);
            Err(Error::NotSupported.into())
        }
    }
}

/// Consume the AppState to convert the input file.
/// 
/// This is the main engine of the app. It processes the AppState to queue up
/// the working functions.
/// Note:  Only RSA Private keys are supported.  Elliptic Curve and Public keys
/// are on the way.
/// 
/// # Arguments
/// * `app_state` - The target output state  
/// * `key_info` - The interpreted input file
pub fn convert(app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    safe_to_convert(app_state, key_info).and_then(convert_key)
}
