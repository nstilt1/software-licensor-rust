use reqwest::Response;
use utils::{crypto::chacha20poly1305::Key, prelude::proto::{prost::Message, protos::{self, pubkeys::{ExpiringEcdhKey, ExpiringEcdsaKey}}}};
use crate::Error;
use crate::server_requests_and_responses::{decrypt_response, encrypt_and_sign_payload};

// product id: TestcVVS-zcVMKinnSw/NcioqdKUlTONp

#[allow(unused)]
pub async fn test_license_activation(req_client: &reqwest::Client, server_keys: (ExpiringEcdhKey, ExpiringEcdsaKey)) -> Result<(), Error> {
    let inner_payload = generate_license_activation_payload();
    let payload = encrypt_and_sign_payload(inner_payload, false, server_keys);
    let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/license_activation_refactor")
        .header("X-Signature", "None")
        .body(payload.encrypted)
        .send()
        .await.unwrap();
    let license_key_files = get_license_key_files(response, payload.symmetric_key).await;
    println!("License key files:\n{}", license_key_files);
    Ok(())
}

#[allow(unused)]
pub fn generate_license_activation_payload() -> Vec<u8> {
    use protos::license_activation_request::{LicenseActivationRequest};
    let req = LicenseActivationRequest {
        license_code: "D5FC-4F3F-2EC9-3F9C-768D-offline-651d".into(),
        //machine_id: "machine_id_1".into(),
        machine_id: "machine_id_5".into(),
        hardware_stats: None,
        product_ids: vec![
            "Test1U58-dmYcq_corvrg5ca19az_Lzef".into(), // perpetual
            "TestCq16-ClKZsVOLN_zFnR9y4EWS4z9o".into(), // trial
            "TestGhDt-jkezEw0aV8L1Pn/bgrpz5gog".into()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_four_of_str() {
        let str = "01234";
        assert_eq!(&str[str.len()-5..], "1234");
    }
}