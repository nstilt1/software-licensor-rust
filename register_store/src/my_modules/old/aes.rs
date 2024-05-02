// aes stuff
use aes_gcm::{
    aead::{KeyInit, Aead, generic_array::GenericArray, Payload},
    Aes128Gcm, Nonce,
};
use rand::Rng;
//use hex;
use base64::{engine::general_purpose, Engine as _};

/**
 * Encrypts data
 * Returns (key, nonce, encrypted string)
 */
pub fn aes_encrypt(data: &str) -> Result<(String, String, String), &str> {
    let mut key_bytes = [0u8; 16];
    rand::thread_rng().fill(&mut key_bytes);

    let key = GenericArray::from_slice(&key_bytes);
    let key_64 = general_purpose::STANDARD.encode(key_bytes);

    let cipher = Aes128Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let nonce_64 = general_purpose::STANDARD.encode(nonce_bytes);

    //let data_generic = GenericArray::from_slice(data.as_bytes());
    //let test = b"TestEncrypt";
    let cipher_text_result = cipher.encrypt(nonce.into(), Payload { msg: data.as_bytes(), aad: b"" });
    if cipher_text_result.is_err() {
        return Err("Error A21");
    }
    let cipher_text = general_purpose::STANDARD.encode(cipher_text_result.unwrap());
    
    return Ok((key_64, nonce_64, cipher_text));
}

pub fn aes_decrypt(k: Vec<u8>, nonce: &str, data: &str) -> Result<String, String> {
    // let mut key_bytes = [0u8];
    let key_slice_result = general_purpose::STANDARD.decode(k);
    if key_slice_result.is_err() {
        return Err(format!("Error A41: {:?}", key_slice_result.unwrap_err()));
    }
    let key_bytes = key_slice_result.unwrap();

    // let mut nonce_bytes = [0u8; 12];
    let nonce_slice_result = general_purpose::STANDARD.decode(nonce);
    if nonce_slice_result.is_err() {
        return Err(format!("Error A46: {:?}" , nonce_slice_result.unwrap_err()));
    }
    let nonce_bytes = nonce_slice_result.unwrap();
    
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes128Gcm::new(key);
    
    let ciphertext_result = general_purpose::STANDARD.decode(data);
    if ciphertext_result.is_err() {
        return Err("Error A59".to_string());
    }
    let ciphertext = ciphertext_result.unwrap();

    let decrypt_result =  cipher.decrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: &ciphertext, aad: b"" });
    //return Ok(String::from_utf8(decrypt_result).unwrap());
    
    if decrypt_result.is_err() {
        /*
        match decrypt_result {
            Err(e) => {
                match e {
                    AeadError::Invalid => println!("FFF"),
                }
            },
            _ => unimplemented!()
        }
        */
        
        return Err(format!("Error A43: {:?}", decrypt_result.unwrap_err()));
    }
    let decrypt = decrypt_result.unwrap();
    let string_result = String::from_utf8(decrypt);
    if string_result.is_err() {
        return Err("Error A48".to_string());
    }
    return Ok(string_result.unwrap());
    
}