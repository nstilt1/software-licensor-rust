use std::time::{SystemTime, UNIX_EPOCH};

use lambda_http::{Response, Body, Error};
use substring::Substring;

pub fn cleanse (text: &str, extra_chars: &str, to_upper: bool) -> String {
    let mut allowed_chars = "ASDFGHJKLQWERTYUIOPZXCVBNM1234567890".to_owned();
    allowed_chars.push_str(extra_chars);
    let mut output = "".to_owned();
    for ch in text.chars() {
        let upper = ch.to_ascii_uppercase();
        if allowed_chars.contains(upper){
            output.push(if to_upper {upper} else {ch});
        }
    }
    output.to_owned()
}

pub fn error_resp(code: u16, message: &str) -> Result<Response<Body>, Error> {
    return Ok(Response::builder()
        .status(code)
        .header("content-type", "text/html")
        .body(message.into())
        .map_err(Box::new)?);
}

pub fn success_resp(message: &str) -> Result<Response<Body>, Error> {
    return Ok(Response::builder()
        .status(200)
        .header("content-type", "text/html")
        .body(message.into())
        .map_err(Box::new)?);
}

pub trait Comparing {
    fn exists_in(self, vector: Vec<&str>) -> bool;
}
impl Comparing for &str {
    fn exists_in(self, vector: Vec<&str>) -> bool {
        return vector.contains(&self);
    }
}
impl Comparing for String {
    fn exists_in(self, vector: Vec<&str>) -> bool {
        return vector.contains(&self.as_str());
    }
}


/**
 * Remove any sabotage from the email address.
 */
pub fn clean_email(input: &str) -> String {
    if input.contains("@gmail.com"){
        let at_sign = input.find('@').unwrap();
        let mut output = input.substring(0, at_sign).to_owned();
        output = output.replace(".", "");
        if output.contains('+') {
            output = output.substring(0, output.find('+').unwrap()).to_owned();
        }
        output.push_str(input.substring(at_sign, input.len()));
        return output;
    }
    return input.to_owned();
}
use crate::my_modules::error::HttpError;

use super::{super::crypto::{rsa::*, aes::*}, to_json::ToJson};

use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct Output {
    data: String,
    key: String,
    nonce: String,
    timestamp: String,
    signature: String,
}
impl Output {
    pub fn new(d: &str, k: &str, n: &str) -> Result<Output, HttpError> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
        let signature_result = format!("{}{}{}{}", &d, &n, &k, timestamp).sign();
        if signature_result.as_ref().is_err() {
            return Err(signature_result.unwrap_err());
        }
        Ok(Output {
            data: d.to_string(),
            key: k.to_string(),
            nonce: n.to_string(),
            timestamp,
            signature: signature_result.unwrap() 
        })
    }
}

pub fn success_response(input: &str, key: &str) -> Result<Response<Body>, Error> {

    let aes_output_result = input.to_string().aes_encrypt();
    if aes_output_result.is_err() {
        return aes_output_result.unwrap_err().respond();
    }
    let aes_output = aes_output_result.unwrap();

    let key_to_encrypt = aes_output.0;
    let nonce = aes_output.1;
    let encrypted_data = aes_output.2;

    let encrypt_key_result = key.to_string().rsa_encrypt(key_to_encrypt);
    if encrypt_key_result.is_err() {
        return encrypt_key_result.unwrap_err().respond();
    }
    let output = Output::new(&encrypted_data, &encrypt_key_result.unwrap(), &nonce);

    if output.as_ref().is_err() {
        return output.unwrap_err()._202("Error CC117").respond();
    }
    let output_json_result = output.unwrap().to_json();
    if output_json_result.as_ref().is_err() {
        return output_json_result.unwrap_err().respond();
    }

    return Ok(Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(output_json_result.unwrap().into())
        .map_err(Box::new)?);
}
