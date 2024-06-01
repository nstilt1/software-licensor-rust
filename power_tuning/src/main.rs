use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;


use reqwest::Response;
use utils::aws_sdk_lambda;
use utils::aws_config;
use aws_sdk_lambda::{Client, Error};
use aws_config::meta::region::RegionProviderChain;
use utils::crypto::chacha20poly1305::aead::Aead;
use utils::crypto::chacha20poly1305::Key;
use utils::crypto::chacha20poly1305::Nonce;
use rand_chacha::{ChaCha8Rng, rand_core::{RngCore, SeedableRng}};
use utils::crypto::p384::{
    ecdh::EphemeralSecret,
    ecdsa::{
        Signature,
        SigningKey,
        signature::Signer
    }
};
use utils::crypto::p384::elliptic_curve::rand_core::OsRng;
use utils::now_as_seconds;
use utils::prelude::proto::{protos, prost::Message};
use utils::prelude::tokio::time::sleep;
use utils::prelude::*;
use chacha20poly1305::KeyInit;
use protos::pubkeys::{PubkeyRepo, ExpiringEcdhKey, ExpiringEcdsaKey};

async fn get_server_pubkeys(client: &reqwest::Client) -> (ExpiringEcdhKey, ExpiringEcdsaKey) {
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

struct Payload {
    pub encrypted: Vec<u8>,
    pub signature: Vec<u8>,
    pub symmetric_key: Key,
}

fn encrypt_and_sign_payload(inner_payload: Vec<u8>, is_handshake: bool, server_keys: (ExpiringEcdhKey, ExpiringEcdsaKey)) -> Payload {
    use protos::request::{DecryptInfo, Request};
    let mut rng = ChaCha8Rng::from_seed([4u8; 32]);
    let signing_key = p384::ecdsa::SigningKey::random(&mut rng);
    let client_id: String = match is_handshake {
        true => "TEST".into(),
        false => "TESThPFV-DpSuh36imnMPQttBfdzWi8d4U66XUJiFEmJIvxiqbxLUmn1ex1x04g_e".into()
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

fn generate_create_product_payload() -> Vec<u8> {
    use protos::create_product_request::CreateProductRequest;
    let req = CreateProductRequest {
        version: "0.0".into(),
        product_name: "Test product".into(),
        product_id_prefix: "Test".into(),
        is_offline_allowed: false,
        max_machines_per_license: 3,
    };
    req.encode_length_delimited_to_vec()
}

fn generate_create_license_payload() -> Vec<u8> {
    use protos::create_license_request::{CreateLicenseRequest, ProductInfo};
    let mut product_info: HashMap<String, ProductInfo> = HashMap::new();
    //product_info.insert()
    let req = CreateLicenseRequest {
        customer_first_name: "Test".into(),
        customer_last_name: "TestLastName".into(),
        customer_email: "test@m.com".into(),
        order_id: "Test Order ID".into(),
        user_id: "Test User ID".into(),
        custom_success_message: "".into(),
        product_info: product_info,
    };
    req.encode_length_delimited_to_vec()
}

fn generate_register_store_payload() -> (Vec<u8>, SigningKey) {
    use protos::register_store_request::{Configs, RegisterStoreRequest};
    let mut rng = ChaCha8Rng::from_seed([4u8; 32]);
    let signing_key = p384::ecdsa::SigningKey::random(&mut rng);
    let pubkey = signing_key.verifying_key().to_sec1_bytes();
    let result = RegisterStoreRequest {
        contact_first_name: "Test First Name".into(),
        contact_last_name: "Test Last Name".into(),
        contact_email: "Testemail@gmail.com".into(),
        store_name: "Test Store Name".into(),
        store_url: "https://test.com".into(),
        discord_username: "testing".into(),
        state: "Test".into(),
        country: "Test".into(),
        public_signing_key: pubkey.to_vec(),
        configs: Some(Configs {
            max_machines_per_license: 3,
            offline_license_frequency_hours: 20,
            perpetual_license_expiration_days: 20,
            perpetual_license_frequency_hours: 20,
            subscription_license_expiration_days: 20,
            subscription_license_expiration_leniency_hours: 20,
            subscription_license_frequency_hours: 20,
            trial_license_expiration_days: 20,
            trial_license_frequency_hours: 20,
        }),
    };
    (result.encode_length_delimited_to_vec(), signing_key)
}

async fn decrypt_response(response: Response, symmetric_key: Key) -> Vec<u8> {
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
async fn get_store_id(response: Response, symmetric_key: Key) -> String {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::register_store_request::RegisterStoreResponse;
    let r = RegisterStoreResponse::decode_length_delimited(decrypted.as_slice()).unwrap();

    r.store_id.clone()
}

async fn get_product_id(response: Response, symmetric_key: Key) -> String {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::create_product_request::CreateProductResponse;
    let r = CreateProductResponse::decode_length_delimited(decrypted.as_slice()).unwrap();
    r.product_id.clone()
}
const GB_PER_MB: f64 = 0.0009765625;
const GB_S_BASE_COST: f64 = 0.0000133334;

fn calculate_costs(memsizes: &[usize], outcomes: Vec<Vec<u128>>) -> Vec<(u128, f64)> {
    let mut costs: Vec<(u128, f64)> = Vec::with_capacity(memsizes.len());
    for i in 0..memsizes.len() {
        let memory = memsizes[i];
        let mut sum = 0;
        for j in 0..outcomes[i].len() {
            sum += outcomes[i][j];
        }
        let average_time_ms = sum / outcomes[i].len() as u128;

        let average_time_s = average_time_ms / 1000;

        let memory_allocated = memory as f64 * GB_PER_MB;
        let total_compute_gb_s = memory_allocated * average_time_s as f64;

        let cost_per_million_invocations = GB_S_BASE_COST * total_compute_gb_s * 1_000_000f64;
        costs.push((average_time_ms, cost_per_million_invocations));
    }
    costs
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let aws_config = aws_config::from_env().region(region_provider).load().await;
    let client = Client::new(&aws_config);
    let req_client = reqwest::Client::new();
    let server_keys = get_server_pubkeys(&req_client).await;
    let memsizes = [128, 256, 384, 512, 650, 700, 750, 800, 850, 900];
    let iterations = 4;
    let mut outcomes = vec![vec![0u128; iterations]; memsizes.len()];
    //let mut store_id: String = String::new();
    let mut product_id: String = String::new();
    for m in 0..memsizes.len() {
        client.update_function_configuration()
            .function_name("create_plugin_refactor")
            .set_memory_size(Some(memsizes[m] as i32))
            .send()
            .await.unwrap();
        sleep(Duration::from_millis(5000)).await;

        for i in 0..iterations {
            let inner_payload = generate_create_product_payload();
            let payload = encrypt_and_sign_payload(inner_payload, false, server_keys.clone());
            
            let start = Instant::now();
            let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/create_plugin_refactor")
            //let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/register_store_refactor")
                .header("X-Signature", payload.signature.to_base64())
                .body(payload.encrypted)
                .send()
                .await.unwrap();
            let end = Instant::now();
            outcomes[m][i] = end.duration_since(start).as_millis();

            product_id = get_product_id(response, payload.symmetric_key).await;
            //store_id = get_store_id(response, payload.symmetric_key).await;

            sleep(Duration::from_millis(1000)).await;
        }
    }

    println!("Register Store Outcomes:");
    let costs_per_memory_allocated = calculate_costs(&memsizes, outcomes);
    println!("Product ID: {}", product_id);
    //println!("Store ID: {}", store_id);
    for i in 0..costs_per_memory_allocated.len() {
        println!("With {} MB of RAM\n{} ms average time\n${} average cost", memsizes[i], costs_per_memory_allocated[i].0, costs_per_memory_allocated[i].1)
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use utils::crypto::p384::ecdsa::signature::Verifier;

    #[test]
    fn signing_and_verifying_roundtrip() {
        let mut rng = ChaCha8Rng::from_seed([4u8; 32]);
        let signing_key = SigningKey::random(&mut rng);
        let data = b"testing roundtrip";
        let signature: Signature = signing_key.sign(data.as_slice());
        let encoded_signature = signature.to_vec();
        
        // verification
        let v_signature: Signature = Signature::from_bytes(encoded_signature.as_slice().try_into().unwrap()).unwrap();

        let verifying_key_bytes = signing_key.verifying_key().to_sec1_bytes();
        let verifying_key = VerifyingKey::from(PublicKey::from_sec1_bytes(&verifying_key_bytes).unwrap());
        assert!(verifying_key.verify(data.as_slice(), &v_signature).is_ok());
    }
}