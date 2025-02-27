use chacha20poly1305::Key;
use proto::protos::pubkeys::{ExpiringEcdhKey, ExpiringEcdsaKey};
use proto::protos::register_store_request::register_store_request::PublicSigningKey;
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use reqwest::Response;
use utils::prelude::proto::protos;
use utils::prelude::*;
use crate::Error;

use crate::server_requests_and_responses::{decrypt_response, encrypt_and_sign_payload};

#[allow(unused)]
pub async fn test_register_store(req_client: &reqwest::Client, server_keys: (ExpiringEcdhKey, ExpiringEcdsaKey)) -> Result<(), Error> {
    let inner_payload = generate_register_store_payload();
    let payload = encrypt_and_sign_payload(inner_payload, true, server_keys);
    let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/register_store_refactor")
        .header("X-Signature", payload.signature.to_base64(false))
        .body(payload.encrypted)
        .send()
        .await.unwrap();

    let store_id = get_store_id(response, payload.symmetric_key).await;
    println!("Store ID: {}", store_id);
    Ok(())
}

use p384::elliptic_curve::sec1::FromEncodedPoint;
#[allow(unused)]
pub fn generate_register_store_payload() -> Vec<u8> {
    use protos::register_store_request::{Configs, RegisterStoreRequest};
    let mut rng = ChaCha8Rng::from_seed([4u8; 32]);
    let signing_key = p384::ecdsa::SigningKey::random(&mut rng);
    let pubkey: PublicKey = PublicKey::from_encoded_point(
        &signing_key
            .verifying_key()
            .to_encoded_point(true)
    ).unwrap();
    let result = RegisterStoreRequest {
        public_signing_key: Some(PublicSigningKey::Pem(pubkey.to_string())),
    };
    result.encode_length_delimited_to_vec()
}

/// Gets a store ID from a RegisterStoreResponse
#[allow(unused)]
pub async fn get_store_id(response: Response, symmetric_key: Key) -> String {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::register_store_request::RegisterStoreResponse;
    let r = RegisterStoreResponse::decode_length_delimited(decrypted.as_slice()).unwrap();

    r.store_id.clone()
}