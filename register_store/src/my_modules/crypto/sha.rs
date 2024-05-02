
use openssl::{sha::Sha256, hash::MessageDigest};

use crate::my_modules::error::HttpError;

/**
 * Salts and hashes an email address
 */
impl Hashing for &str {
    fn to_hash(&self) -> Result<Vec<u8>, HttpError> {

        let result = openssl::hash::hash(MessageDigest::sha256(), self.as_bytes());
        if result.is_err() {
            return Err("Error CCS12".into());
        }
        return Ok(result.unwrap().to_vec());

        /*
        let mut hasher = Sha256::new();

        hasher.update(self.as_bytes());

        return hasher.finish().to_vec();
        */
    }
}
impl Hashing for String {
    fn to_hash(&self) -> Result<Vec<u8>, HttpError> {
        return self.as_str().to_hash();
    }
}
/**
 * Hashes a string
 */

pub trait Hashing {
    fn to_hash(&self) -> Result<Vec<u8>, HttpError>;
}