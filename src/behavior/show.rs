//! Display the key info on the terminal
//! 
use anyhow::Result;
use crate::app_state::AppState;
use crate::key_info::KeyInfo;

pub fn show(_app_state: &mut AppState, key_info: &KeyInfo) -> Result<()> {
    println!("{:}", key_info);
    Ok(())
}

