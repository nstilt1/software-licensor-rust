use reqwest::Response;
use utils::{crypto::chacha20poly1305::Key, prelude::proto::{prost::Message, protos}};

use crate::server_requests_and_responses::decrypt_response;

// product id: TestcVVS-zcVMKinnSw/NcioqdKUlTONp

#[allow(unused)]
pub fn generate_license_activation_payload() -> Vec<u8> {
    use protos::license_activation_request::{LicenseActivationRequest};
    let req = LicenseActivationRequest {
        license_code: "7E32-F88B-4235-3198-EEB1".into(),
        machine_id: "machid1".into(),
        hardware_stats: None,
        product_ids: vec![
            "TestfxcJ-uldVDjRWqIPhjc1BXqaijHN1".into(), 
            "TestKvXk-scAX/xccsTlqCGFHnfI9_deo".into()
        ],
    };
    req.encode_length_delimited_to_vec()
}
#[allow(unused)]
pub async fn get_license_key_files(response: Response, symmetric_key: Key) -> String {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::license_activation_request::LicenseActivationResponse;
    let r = LicenseActivationResponse::decode_length_delimited(decrypted.as_slice()).unwrap();
    format!("Key Files: {:?}\n\nsignatures: {:?}\nErrors: {:?}", r.key_files, r.key_file_signatures, r.licensing_errors)
}