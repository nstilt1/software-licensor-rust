use reqwest::Response;
use utils::{crypto::chacha20poly1305::Key, prelude::proto::{prost::Message, protos}};

use crate::server_requests_and_responses::decrypt_response;


pub fn generate_create_product_payload() -> Vec<u8> {
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

pub async fn get_product_id(response: Response, symmetric_key: Key) -> String {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::create_product_request::CreateProductResponse;
    let r = CreateProductResponse::decode_length_delimited(decrypted.as_slice()).unwrap();
    r.product_id.clone()
}