//! # Error
//!
//! Custom Error types for client

use std::error;
use std::fmt;
use bitcoin::util::bip32::Error as Bip32Error;
use reqwest::Error as ReqwestError;
/// State Entity library specific errors
#[derive(Debug, Deserialize)]
pub enum CError {
    /// Wallet
    WalletError(WalletErrorType, String),
    /// State entity Athorisation failed
    StateEntityError(String),
    /// Schnorr
    SchnorrError(String),
    /// Generic error from string error message
    Generic(String),
    /// Inherit all errors from bip32
    Bip32(String),
    /// Inherit error from reqwest
    Reqwest(String)
}

impl From<String> for CError {
    fn from(e: String) -> CError {
        CError::Generic(e)
    }
}

impl From<Bip32Error> for CError {
    fn from(e: Bip32Error) -> CError {
        CError::Bip32(e.to_string())
    }
}
impl From<ReqwestError> for CError {
    fn from(e: ReqwestError) -> CError {
        CError::Reqwest(e.to_string())
    }
}

/// Input parameter error types
#[derive(Debug, Deserialize)]
pub enum WalletErrorType {
    /// No shared wallet found for ID
    SharedWalletNotFound
}

impl WalletErrorType {
    fn as_str(&self) -> &'static str {
        match *self {
            WalletErrorType::SharedWalletNotFound => "No shared wallet found.",
        }
    }
}

impl fmt::Display for CError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CError::Generic(ref e) => write!(f, "generic Error: {}", e),
            CError::StateEntityError(ref e) => write!(f, "State Entity Error: {}", e),
            CError::SchnorrError(ref e) => write!(f, "Schnorr Error: {}", e),
            CError::WalletError(ref error, ref value) => write!(f, "Wallet Error: {} (value: {})", error.as_str(), value),
            CError::Bip32(ref e) => write!(f, "Bip32 Error: {}", e),
            CError::Reqwest(ref e) => write!(f, "Reqwest Error: {}", e),
        }
    }
}

impl error::Error for CError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}
