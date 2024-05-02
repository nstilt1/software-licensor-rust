use lambda_http::{Body, Error, Response};


use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct AesOut {
    plugin_id: String,
    license_types: String,
    languages: String,
    juce_public_key: String
}
impl AesOut {
    pub fn new(plug: &str, license_type_vec: Vec<String>, langs: Vec<String>, public_key: &str) -> Self {
        AesOut { 
            plugin_id: plug.to_owned(), 
            license_types: license_type_vec.to_owned().join(","), 
            languages: langs.to_owned().join(","),
            juce_public_key: public_key.to_owned()
        }
    }
    pub fn to_json(&self) -> Result<String, String> {
        let json_result = serde_json::to_string(&self);
        if json_result.is_err() {
            return Err(json_result.unwrap_err().to_string());
        }
        return Ok(json_result.unwrap());
    }
}

pub fn cleanse (text: &str, extra_chars: &str) -> String {
    let mut allowed_chars = "ASDFGHJKLQWERTYUIOPZXCVBNM1234567890".to_owned();
    allowed_chars.push_str(extra_chars);
    let mut output = "".to_owned();
    for ch in text.chars() {
        let upper = ch.to_ascii_uppercase();
        if allowed_chars.contains(upper){
            output.push(upper);
        }
    }
    output.to_owned()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Output {
    data: String,
    nonce: String,
    key: String,
    timestamp: String,
    signature: String
}
impl Output {
    pub fn new(d: &str, k: &str, n: &str) -> Result<Output, HttpError> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
        let sign_result = format!("{}{}{}{}", d, n, k, timestamp).sign();
        if sign_result.is_err() {return Err((500, "Error CPO55").into());}



        Ok(Output {
            data: d.to_string(),
            nonce: n.to_string(),
            key: k.to_string(),
            timestamp,
            signature: sign_result.unwrap()
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

    let encrypt_key_result = key.to_owned().rsa_encrypt(key_to_encrypt);
    if encrypt_key_result.is_err() {
        return encrypt_key_result.unwrap_err().respond();
    }
    let output = Output::new(&encrypted_data, &encrypt_key_result.unwrap(), &nonce);
    if output.is_err() {return output.unwrap_err().respond();}
    let output_json_result = output.unwrap().to_json();
    if output_json_result.is_err() {
        return output_json_result.unwrap_err()._202("Error CJ90").respond();
    }

    return Ok(Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(output_json_result.unwrap().into())
        .map_err(Box::new)?);
}

pub fn error_resp(code: u16, message: &str) -> Result<Response<Body>, Error> {
    return Ok(Response::builder()
        .status(code)
        .header("content-type", "text/html")
        .body(message.into())
        .map_err(Box::new)?);
}



use substring::Substring;
use std::{collections::HashMap, time::{SystemTime, UNIX_EPOCH}};
use num_bigint::BigUint;
use num_traits::Num;

use super::{crypto::{rsa::Crypto, aes::CryptoAES}, error::HttpError, utils::to_json::ToJson};
pub fn mix_chars_up(key: &String) -> String {

    let mut mixed = "".to_owned();
    let mut i = 0;
    while i < key.len() {
        if key.len() - i != 1 {
            mixed.push(key.chars().nth(i+1).unwrap());
            mixed.push(key.chars().nth(i).unwrap());
        }else{
            mixed.push(key.chars().nth(i).unwrap());
        }
        i += 2;
    }

    return mixed;
}

pub fn switch_up_chars(mix_chars: &String, dict: &HashMap<char, char>, is_encrypt: bool) -> String {
    let mut switched_up = "".to_owned();
    let mut switch_2 = "".to_owned();
    if is_encrypt {
        for i in mix_chars.chars() {
        
            switched_up.push(dict.get(&i.to_ascii_uppercase()).unwrap().to_owned());
        
        }
        switch_2.push_str(&switched_up.substring(5, 8));
        switch_2.push_str(&switched_up.substring(0, 5));
        switch_2.push_str(&switched_up.substring(8,switched_up.len()));
        //println!("is_encrypt mode successful");
    }else{
        for i in mix_chars.chars() {
            switched_up.push(dict.get(&i.to_ascii_uppercase()).unwrap().to_owned());
        }
        switch_2.push_str(&switched_up.substring(3, 8));
        switch_2.push_str(&switched_up.substring(0, 3));
        switch_2.push_str(&switched_up.substring(8, switched_up.len()));
        
    }

    return switch_2;
}

pub fn encrypt_id(key : &str, is_encrypt : bool, is_license: bool) -> String {

    let dict: HashMap<char, char>;
    let key_length: usize;
    if !is_license {
        key_length = 23;
        dict = HashMap::from([
            ('4', '2'),
            ('Z', 'P'),
            ('K', 'O'),
            ('N', 'J'),
            ('P', 'E'),
            ('D', '9'),
            ('L', 'R'),
            ('B', 'I'),
            ('7', 'T'),
            ('M', '6'),
            ('Q', '5'),
            ('F', 'X'),
            ('J', 'H'),
            ('9', '7'),
            ('C', 'Y'),
            ('2', '3'),
            ('O', '0'),
            ('8', 'M'),
            ('1', 'Q'),
            ('3', '1'),
            ('5', 'V'),
            ('S', 'U'),
            ('X', 'G'),
            ('R', 'K'),
            ('Y', 'F'),
            ('E', '8'),
            ('I', 'C'),
            ('W', 'W'),
            ('A', 'S'),
            ('H', 'B'),
            ('0', 'L'),
            ('U', 'N'),
            ('V', '4'),
            ('6', 'A'),
            ('G', 'Z'),
            ('T', 'D'),
        ]);
    }else{
        key_length = 32;
        dict = HashMap::from([
            ('W', 'A'),
            ('T', 'T'),
            ('1', 'U'),
            ('L', 'M'),
            ('F', '6'),
            ('S', '9'),
            ('U', '8'),
            ('C', 'Z'),
            ('K', 'Y'),
            ('Z', 'V'),
            ('5', 'R'),
            ('G', 'S'),
            ('D', 'E'),
            ('Q', 'O'),
            ('H', '3'),
            ('N', 'F'),
            ('I', 'J'),
            ('V', '5'),
            ('R', 'G'),
            ('O', 'P'),
            ('0', '4'),
            ('8', '1'),
            ('B', 'D'),
            ('X', 'N'),
            ('6', 'K'),
            ('A', 'C'),
            ('P', 'H'),
            ('7', 'Q'),
            ('Y', 'X'),
            ('4', 'I'),
            ('E', 'L'),
            ('3', '2'),
            ('2', '0'),
            ('J', '7'),
            ('9', 'B'),
            ('M', 'W'),
        ]);
    }
    
    let mut reverse_hashmap = HashMap::new();
    
    for (&name, &value_) in &dict.to_owned() {
        reverse_hashmap.insert(
            value_.to_owned(),
            name.to_owned(),
        );
    }

    if is_encrypt {
        //return "".to_owned();
        // DELETE
        //let mut test_big_int_error = BigUint::from_str_radix(&key, 36).err();
        //if !test_big_int_error.is_none() {
            //return test_big_int_error.unwrap().to_string();
        //}
        let mut result = BigUint::from_str_radix(&key, 36).unwrap();
        
        if is_license {
            result += BigUint::from_str_radix("HJ5X5L2YFKV3V2FGUWF4DLJ27VZWC8B28C", 36).unwrap();
        }else{
            result += BigUint::from_str_radix("HV9YMVBEE6PQT3L3ZKFJR8WSMD", 36).unwrap();
        }

        // reverse
        let reversed = result.to_str_radix(36).chars().rev().collect::<String>();
        // mix them
        
        let mix_chars = mix_chars_up(&reversed);
        
        let encrypted = switch_up_chars(&mix_chars, &dict, true);
        return encrypted;
    }else{
        let unencrypted1 = switch_up_chars(&key.to_owned(), &reverse_hashmap, false);
        //println!("unencrypted1 = {:?}", unencrypted1);
        let mixed_chars = mix_chars_up(&unencrypted1);
        //println!("mixed_chars = {:?}", mixed_chars);
        let reversed = mixed_chars.chars().rev().collect::<String>();
        let mut result = BigUint::from_str_radix(&reversed, 36).unwrap();
        if is_license {
            result -= BigUint::from_str_radix("HJ5X5L2YFKV3V2FGUWF4DLJ27VZWC8B28C", 36).unwrap();
        }else{
            result -= BigUint::from_str_radix("HV9YMVBEE6PQT3L3ZKFJR8WSMD", 36).unwrap();
        }
        let result_1 = result.to_str_radix(36).to_ascii_uppercase();
        let mut final_result = "".to_owned();
        
        if result_1.len() < key_length {
            let mut i = 0;
            while i < key_length - result_1.len() {
                final_result.push('0');
                i += 1;
            }
            final_result.push_str(&result_1);
        }else{
            final_result = result_1;
        }
        return final_result.to_owned();
    }
}
