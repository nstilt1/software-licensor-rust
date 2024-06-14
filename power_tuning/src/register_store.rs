use chacha20poly1305::Key;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use reqwest::Response;
use utils::crypto::p384::ecdsa::SigningKey;
use utils::prelude::proto::{protos, prost::Message};
use utils::prelude::*;

use crate::server_requests_and_responses::decrypt_response;

#[allow(unused)]
pub fn generate_register_store_payload() -> (Vec<u8>, SigningKey) {
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

/// Gets a store ID from a RegisterStoreResponse
#[allow(unused)]
pub async fn get_store_id(response: Response, symmetric_key: Key) -> String {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::register_store_request::RegisterStoreResponse;
    let r = RegisterStoreResponse::decode_length_delimited(decrypted.as_slice()).unwrap();

    r.store_id.clone()
}