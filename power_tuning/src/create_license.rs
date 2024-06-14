use reqwest::Response;
use utils::{base64::Base64Vec, crypto::chacha20poly1305::Key, prelude::proto::{prost::Message, protos::{self, pubkeys::{ExpiringEcdhKey, ExpiringEcdsaKey}}}};
use std::collections::HashMap;
use crate::Error;
use crate::server_requests_and_responses::{decrypt_response, encrypt_and_sign_payload};

// product id: TestcVVS-zcVMKinnSw/NcioqdKUlTONp

#[allow(unused)]
pub async fn test_create_license(req_client: &reqwest::Client, server_keys: (ExpiringEcdhKey, ExpiringEcdsaKey)) -> Result<(), Error> {
    let inner_payload = generate_create_license_payload();
    let payload = encrypt_and_sign_payload(inner_payload, false, server_keys);
    let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/create_license_refactor")
        .header("X-Signature", payload.signature.to_base64())
        .body(payload.encrypted)
        .send()
        .await.unwrap();

    let license_code = get_license_code(response, payload.symmetric_key).await;
    println!("License code: {}", license_code);
    Ok(())
}

#[allow(unused)]
pub fn generate_create_license_payload() -> Vec<u8> {
    use protos::create_license_request::{CreateLicenseRequest, ProductInfo};
    let mut product_info: HashMap<String, ProductInfo> = HashMap::new();
    product_info.insert("Test1U58-dmYcq_corvrg5ca19az_Lzef".into(), ProductInfo {
        license_type: "perpetual".into(),
        quantity: 1,
        subtotal: "0".into()
    });
    product_info.insert("TestCq16-ClKZsVOLN_zFnR9y4EWS4z9o".into(), ProductInfo {
        license_type: "trial".into(),
        quantity: 1,
        subtotal: "0".into()
    });
    product_info.insert("TestGhDt-jkezEw0aV8L1Pn/bgrpz5gog".into(), ProductInfo {
        license_type: "subscription".into(),
        quantity: 1,
        subtotal: "0".into(),
    });
    let req = CreateLicenseRequest {
        customer_first_name: "Test".into(),
        customer_last_name: "TestLastName".into(),
        customer_email: "test@m.com".into(),
        order_id: "Test Order ID".into(),
        user_id: "Test User ID222".into(),
        custom_success_message: "".into(),
        product_info,
    };
    req.encode_length_delimited_to_vec()
}
#[allow(unused)]
pub async fn get_license_code(response: Response, symmetric_key: Key) -> String {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::create_license_request::CreateLicenseResponse;
    let r = CreateLicenseResponse::decode_length_delimited(decrypted.as_slice()).unwrap();
    r.license_code.to_owned()
}