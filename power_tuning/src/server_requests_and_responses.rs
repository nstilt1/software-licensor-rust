use proto::protos::request::decrypt_info::ClientEcdhPubkey;
use proto::protos::response::EcdhKey;
use reqwest::Response;
use utils::crypto::chacha20poly1305::aead::Aead;
use utils::crypto::chacha20poly1305::Key;
use utils::crypto::chacha20poly1305::Nonce;
use rand_chacha::{ChaCha8Rng, rand_core::{RngCore, SeedableRng}};
use utils::crypto::p384::{
    ecdh::EphemeralSecret,
    ecdsa::signature::Signer
};
use utils::crypto::p384::elliptic_curve::rand_core::OsRng;
use utils::now_as_seconds;
use utils::prelude::proto::protos;
use utils::prelude::*;
use chacha20poly1305::KeyInit;
use protos::pubkeys::{PubkeyRepo, ExpiringEcdhKey, ExpiringEcdsaKey};

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

const NEXT_KEY_FILE_PATH: &str = "next_key.bin";

pub struct Payload {
    pub encrypted: Vec<u8>,
    pub signature: Vec<u8>,
    pub symmetric_key: Key,
}

pub fn encrypt_and_sign_payload(inner_payload: Vec<u8>, is_handshake: bool, server_keys: (ExpiringEcdhKey, ExpiringEcdsaKey)) -> Payload {
    use protos::request::{DecryptInfo, Request};
    let mut rng = ChaCha8Rng::from_seed([4u8; 32]);
    let signing_key = p384::ecdsa::SigningKey::random(&mut rng);
    let client_id: String = match is_handshake {
        true => "TEST".into(),
        false => "TESTfW4_-8w1H0NZuntJ2hb/mWZDDHQOvSx/BX5ORIG5xAb4CxEpBPLZ2wqm/K4lO".into()
    };
    let (server_ecdh_key_id, ecdh_pubkey) = if Path::new(NEXT_KEY_FILE_PATH).exists() {
        let mut file = File::open(NEXT_KEY_FILE_PATH).unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
        let next_key = EcdhKey::decode_length_delimited(buffer.as_slice()).unwrap();
        println!("Using next_key.bin");
        (next_key.ecdh_key_id, next_key.ecdh_public_key)
    } else {
        (server_keys.0.ecdh_key_id, server_keys.0.ecdh_public_key)
    };
    
    let server_ecdsa_key_id = server_keys.1;
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let shared_secret = ephemeral_secret.diffie_hellman(&PublicKey::from_sec1_bytes(&ecdh_pubkey).unwrap());
    let salt = b"Test salt";
    let mut key = Key::default();
    let kdf = shared_secret.extract::<sha2::Sha384>(Some(salt));
    let info = b"Testing info";
    kdf.expand(info, &mut key).expect("Should be short enough");

    let encryptor = ChaCha20Poly1305::new(&key);
    let mut nonce: Nonce = Nonce::default();
    OsRng.fill_bytes(&mut nonce);
    let mut encrypted_data = encryptor.encrypt(&nonce, inner_payload.as_slice()).unwrap();

    // prepend the nonce to the encrypted data
    encrypted_data.splice(0..0, nonce);
    
    let result = Request {
        symmetric_algorithm: "chacha20-poly1305".into(),
        client_id,
        data: encrypted_data,
        decryption_info: Some(DecryptInfo {
            server_ecdh_key_id,
            client_ecdh_pubkey: Some(ClientEcdhPubkey::Pem(ephemeral_secret.public_key().to_string())),
            ecdh_info: info.to_vec(),
            ecdh_salt: salt.to_vec(),
        }),
        server_ecdsa_key_id: server_ecdsa_key_id.ecdsa_key_id,
        timestamp: now_as_seconds(),
    };
    let p = result.encode_length_delimited_to_vec();
    let signature: Signature = signing_key.sign(&p);
    Payload { 
        encrypted: p, 
        signature: signature.to_der().as_bytes().to_vec(),
        symmetric_key: key,
    }
}

pub async fn get_server_pubkeys(client: &reqwest::Client) -> (ExpiringEcdhKey, ExpiringEcdsaKey) {
    let f = client.get("https://software-licensor-public-keys.s3.amazonaws.com/public_keys").send().await.unwrap();
    let pubkey_repo = match PubkeyRepo::decode_length_delimited(f.bytes().await.unwrap()) {
        Ok(p) => p,
        Err(e) => panic!("Failed to decode: {}", e.to_string())
    };
    let ecdh_keys = &pubkey_repo.ecdh_keys;
    let ecdsa_key = pubkey_repo.ecdsa_key.unwrap();
    // the length is a multiple of 2
    let ecdh_keys_len = ecdh_keys.len();
    let index = OsRng.next_u32() & (ecdh_keys_len as u32 - 1);
    let ecdh_key = ecdh_keys[index as usize].clone();
    (ecdh_key, ecdsa_key)
}

pub async fn decrypt_response(response: Response, symmetric_key: Key) -> Vec<u8> {
    use protos::response::Response as ProtoResponse;
    let body = match response.bytes().await {
        Ok(v) => v,
        Err(_e) => {
            println!("Body was not bytes");
            panic!()
        }
    };
    let resp = if let Ok(r) = ProtoResponse::decode_length_delimited(body.as_ref()) {
        r
    } else {
        panic!("Response was not decodable: {}", &String::from_utf8(body.as_ref().to_vec()).unwrap());
    };

    // write the next key to a local file so that we can test new keys to see if
    // they work or not
    let mut file = File::create(NEXT_KEY_FILE_PATH).unwrap();
    file.write_all(&resp.next_ecdh_key.unwrap().encode_length_delimited_to_vec()).unwrap();

    let decryptor = ChaCha20Poly1305::new(&symmetric_key);
    let nonce: &Nonce = Nonce::from_slice(&resp.data[..12]);
    let decrypted = decryptor.decrypt(nonce, &resp.data[12..]).unwrap();
    decrypted
}

#[cfg(test)]
mod tests {
    use utils::base64::Base64String;

    use super::*;

    #[test]
    fn signature_format() {
        let sig_b64 = "MGUCMQD3mB/dwTvyuM+tjcxaynBEwuHhuVoJGFjSLgm6MenfY1SfeIHRQQE5Kv2CFRl8QZkCMFguuci+Uo9VMopQ28yQq7x9bcfdsrVneg2kO5jkjIneX2yVwNVE2h9Aw6dEpKnu6w";
        let sig = sig_b64.from_base64().unwrap();
        let s: Result<Signature, _> = Signature::from_der(&sig);
        //let s: Result<SignatureBytes<NistP384>, _> = sig.as_slice().try_into();
        assert!(s.is_ok(), "Signature was not valid; length = {}, bits = {}", sig.len(), sig.len() * 8);
    }

    #[test]
    fn signature_format_2() {
        let key = p384::ecdsa::SigningKey::random(&mut OsRng);
        let sig: Signature = key.sign(&[3,2,1,3,4,3,23,1,3]);
        let b = sig.to_bytes();
        println!("Signature bytes length = {}", b.len());
    }
}