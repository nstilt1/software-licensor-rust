use base64::prelude::{Engine as _, BASE64_STANDARD};
use reqwest::Response;
use utils::{base64::Base64Vec, crypto::chacha20poly1305::Key, prelude::proto::{prost::Message, protos::{self, pubkeys::{ExpiringEcdhKey, ExpiringEcdsaKey}}}};
use crate::Error;
use crate::server_requests_and_responses::{decrypt_response, encrypt_and_sign_payload};

#[allow(unused)]
pub async fn test_create_product(req_client: &reqwest::Client, server_keys: (ExpiringEcdhKey, ExpiringEcdsaKey)) -> Result<(), Error> {
    let inner_payload = generate_create_product_payload();
    let payload = encrypt_and_sign_payload(inner_payload, false, server_keys);
    let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/create_plugin_refactor")
        .header("X-Signature", payload.signature.to_base64(false))
        .body(payload.encrypted)
        .send()
        .await.unwrap();

    let (product_id, pubkey) = get_product_id(response, payload.symmetric_key).await;
    println!("Product ID: {}", product_id);
    println!("Public Key: {}", pubkey);
    Ok(())
}

pub fn generate_create_product_payload() -> Vec<u8> {
    use protos::create_product_request::CreateProductRequest;
    let req = CreateProductRequest {
        version: "1.0".into(),
        product_name: "Test product".into(),
        product_id_prefix: "TestCq16-ClKZsVOLN_zFnR9y4EWS4z9o".into(),
        is_offline_allowed: true,
        max_machines_per_license: 3,
    };
    req.encode_length_delimited_to_vec()
}

pub async fn get_product_id(response: Response, symmetric_key: Key) -> (String, String) {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::create_product_request::CreateProductResponse;
    let r = CreateProductResponse::decode_length_delimited(decrypted.as_slice()).unwrap();
    let pubkey_bytes = &r.product_public_key;
    let encoded_pubkey = BASE64_STANDARD.encode(pubkey_bytes);
    (r.product_id.clone(), encoded_pubkey)
}