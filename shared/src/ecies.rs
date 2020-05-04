use extern crate ecies;
use bitcoin::util::key::{ PublicKey, PrivateKey };
use serde::{Serialize, Deserialize}
use crate::server::util::generate_keypair;

//Encrypted serialization/deserialization
trait Encryptable: Serialize, Deserialize{
    fn to_encrypted_bytes(&self, pubkey: &PublicKey) -> Result<Vec<u8>>{
        let serialized = serde_json::to_string(self).unwrap().as_bytes();
        Ok(ecies::encrypt(&pubkey.serialize(), serialized.as_bytes()).unwrap());
    }

    fn from_encrypted_bytes(&self, privkey: &PrivateKey, ec: &[u8]) ->Result<Self>{
        let serialized = String::from_utf8(ecies::decrypt(&privkey.serialize(), ec).unwrap())
        let deserialized: Self = serde_json::from_str(&serialized).unwrap();
        Ok(deserialized)
    }
}

#[derive(Encryptable)]
struct TestStruct {
    firstItem: String,
    secondItem: u32,
}

/// ecies library specific errors
#[derive(Debug, Deserialize)]
pub enum ECIESError {
    Generic(String),
    EncryptionError(String),
}

impl From<String> for ECIESError {
    fn from(e: String) -> ECIESError {
        ECIESError::Generic(e)
    }
}

impl fmt::Display for ECIESError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ECIESError::Generic(ref e) => write!(f, "generic Error: {}", e),
            ECIESError::EncryptionError(ref e) => write!(f,"EncryptionError: {}",e),
        }
    }
}

impl error::Error for ECIESError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}

impl Responder<'static> for ECIESError {
    fn respond_to(self, _: &Request) -> ::std::result::Result<Response<'static>, Status> {
        Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new(format!("{}", self)))
            .ok()
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_encrypt_decrypt_struct() {
        let ts = TestStruct{firstItem: "test message", secondItem: 42}
        let pk, sk = 
        let tse = ts.to_encrypted_bytes()
        

        let ps = EncryptableString::from("This is a secret message.")
        let 
    }

    #[test]
    fn test_bad_add() {
        // This assert would fire and test will fail.
        // Please note, that private functions can be tested too!
        assert_eq!(bad_add(1, 2), 3);
    }
}
