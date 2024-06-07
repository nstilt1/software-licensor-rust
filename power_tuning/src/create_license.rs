use reqwest::Response;
use utils::{crypto::chacha20poly1305::Key, prelude::proto::{prost::Message, protos}};
use std::collections::HashMap;

use crate::server_requests_and_responses::decrypt_response;

// product id: TestcVVS-zcVMKinnSw/NcioqdKUlTONp

#[allow(unused)]
pub fn generate_create_license_payload() -> Vec<u8> {
    use protos::create_license_request::{CreateLicenseRequest, ProductInfo};
    let mut product_info: HashMap<String, ProductInfo> = HashMap::new();
    product_info.insert("TestfxcJ-uldVDjRWqIPhjc1BXqaijHN1".into(), ProductInfo {
        license_type: "perpetual".into(),
        quantity: 1,
        subtotal: "0".into()
    });
    product_info.insert("TestKvXk-scAX/xccsTlqCGFHnfI9_deo".into(), ProductInfo {
        license_type: "trial".into(),
        quantity: 1,
        subtotal: "0".into()
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