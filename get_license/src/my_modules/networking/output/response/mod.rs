use std::time::{SystemTime, UNIX_EPOCH};

use serde_derive::{Deserialize, Serialize};

use crate::my_modules::{
     
    crypto::{ 
        rsa::Crypto, 
    },
};

use super::{error::HttpError};

#[derive(Serialize, Deserialize, Debug)]
pub struct HttpResponse {
    data: String,
    nonce: String,
    key: String,
    timestamp: String,
    signature: String,
}

impl HttpResponse {
    pub fn new(aes_output: ([u8; 16], String, String), pub_key: &str) -> Result<HttpResponse, HttpError> {
        // initialize a license Object
        let encrypted_key_result = pub_key.to_owned().rsa_encrypt(aes_output.0);
        if encrypted_key_result.as_ref().is_err() {
            return Err(encrypted_key_result.unwrap_err());
        }
        let encrypted_key = encrypted_key_result.unwrap();
        
        let data = aes_output.2;
        let nonce = aes_output.1;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
        let sign_result = format!("{}{}{}{}", &data, &nonce, &encrypted_key, &timestamp).sign();
        if sign_result.as_ref().is_err() {
            return Err(sign_result.unwrap_err());
        }
        return Ok(HttpResponse { 
            data, 
            key: encrypted_key.to_owned(),
            nonce, 
            timestamp, 
            signature: sign_result.unwrap()
        });
    }
}