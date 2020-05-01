use extern crate ecies;
use bitcoin::util::key::{ PublicKey, PrivateKey };

//Encrypted serialization/deserialization
trait Encryptable:  std::clone::Clone, Serialize {
    fn encrypt_with_pubkey(&self, pubkey: &PublicKey) -> Ok<EncryptedBytes>{
        Ok(EncryptedBytes::from_static(&ecies::encrypt(pubkey.serialize(),&self.to_bytes())))
    }
}

struct EncryptedBytes(Bytes);

impl EncryptedBytes {
    fn decrypt_with_privkey(&self, privkey: &PrivateKey) -> Ok<Bytes> {
        Ok(Bytes::from(&ecies::decrypt(&privkey.serialize(), self.as_slice())?))
    }
}

trait FromEncryptedBytes: Deserialize{
    fn from_encrypted_bytes(&self, data: &EncryptedBytes, privkey: &PrivateKey) -> Result<Self>{
        self.from_slice(data.decrypt_with_privkey(privkey)?)
    }
}

#[derive(Encryptable)]
struct EncryptableString(String);

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
    fn test_encrypt_decrypt_string() {
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
