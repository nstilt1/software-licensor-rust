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
        false => "TESTuiQO-Kp6JXjPeKIh7DT/iPpNFnZhN2NYT0ITpltBLqlmvJ71PoA5UU_6ZnmB4".into()
    };
    let (server_ecdh_key_id, ecdh_pubkey) = (server_keys.0.ecdh_key_id, server_keys.0.ecdh_public_key);
    
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
        symmetric_algorithm: "chacha20poly1305".into(),
        client_id,
        data: encrypted_data,
        decryption_info: Some(DecryptInfo {
            server_ecdh_key_id,
            client_ecdh_pubkey: ephemeral_secret.public_key().to_sec1_bytes().to_vec(),
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
        signature: signature.to_vec(),
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

    let decryptor = ChaCha20Poly1305::new(&symmetric_key);
    let nonce: &Nonce = Nonce::from_slice(&resp.data[..12]);
    let decrypted = decryptor.decrypt(nonce, &resp.data[12..]).unwrap();
    decrypted
}