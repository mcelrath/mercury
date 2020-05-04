//! Util
//!
//! Utilities methods useful to both client and server

type Result<T> = std::result::Result<T, UtilError>;

use rand::rngs::OsRng;
use bitcoin::util;
use bitcoin::secp256k1::{ Secp256k1, key::SecretKey };
use bitcoin::blockdata::transaction::{ TxIn, TxOut, Transaction };
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::opcodes::OP_TRUE;
use bitcoin::util::{ address::Address, amount::Amount };
use bitcoin::network::constants::Network;

use rocket::http::{ Status, ContentType };
use rocket::Response;
use rocket::Request;
use rocket::response::Responder;
use std::error;
use std::fmt;
use std::io::Cursor;

pub const NETWORK: bitcoin::network::constants::Network = Network::Regtest;

pub fn reverse_hex_str(hex_str: String) -> Result<String> {
    if hex_str.len() % 2 != 0 {
        return Err(UtilError::FormatError(String::from("Invalid sig hash - Odd number of characters.")))
    }
    let mut hex_str = hex_str.chars().rev().collect::<String>();
    let mut result = String::with_capacity(hex_str.len());
    unsafe {
        let hex_vec = hex_str.as_mut_vec();
        for i in (0..hex_vec.len()).step_by(2) {
            result.push(char::from(hex_vec[i+1]));
            result.push(char::from(hex_vec[i]));
        }
    }
    Ok(result)
}


/// generate bitcoin::util::key key pair
pub fn generate_keypair() -> (util::key::PrivateKey, util::key::PublicKey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng::new().expect("OsRng");
    let secret_key = SecretKey::new(&mut rng);
    let priv_key = util::key::PrivateKey{
        compressed: false,
        network: NETWORK,
        key: secret_key
    };
    let pub_key = util::key::PublicKey::from_private_key(&secp, &priv_key);
    return (priv_key, pub_key)
}



/// State Entity library specific errors
#[derive(Debug, Deserialize)]
pub enum UtilError {
    /// Generic error from string error message
    Generic(String),
    /// Invalid argument error
    FormatError(String)
}

impl From<String> for UtilError {
    fn from(e: String) -> UtilError {
        UtilError::Generic(e)
    }
}

impl fmt::Display for UtilError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UtilError::Generic(ref e) => write!(f, "generic Error: {}", e),
            UtilError::FormatError(ref e) => write!(f,"Format Error: {}",e),
        }
    }
}

impl error::Error for UtilError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}

impl Responder<'static> for UtilError {
    fn respond_to(self, _: &Request) -> ::std::result::Result<Response<'static>, Status> {
        Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new(format!("{}", self)))
            .ok()
    }
}
