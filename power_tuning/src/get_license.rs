use reqwest::Response;
use utils::{crypto::chacha20poly1305::Key, prelude::proto::{prost::Message, protos}};

use crate::server_requests_and_responses::decrypt_response;

// product id: TestcVVS-zcVMKinnSw/NcioqdKUlTONp

#[allow(unused)]
pub fn generate_get_license_payload() -> Vec<u8> {
    use protos::get_license_request::{GetLicenseRequest};
    let req = GetLicenseRequest {
        user_id: "Test User ID222".into()
    };
    req.encode_length_delimited_to_vec()
}
#[allow(unused)]
pub async fn get_license_data(response: Response, symmetric_key: Key) -> String {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::get_license_request::GetLicenseResponse;
    let r = GetLicenseResponse::decode_length_delimited(decrypted.as_slice()).unwrap();
    format!("License Code: {}\nLicense Info: {:?}\nOffline code: {}", r.license_code, r.licensed_products, r.offline_code)
}