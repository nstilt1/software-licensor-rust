use reqwest::Response;
use utils::{base64::Base64Vec, crypto::chacha20poly1305::Key, prelude::proto::{prost::Message, protos::{self, get_license_request::GetLicenseResponse, pubkeys::{ExpiringEcdhKey, ExpiringEcdsaKey}}}};
use crate::{Error, USER_ID};
use crate::server_requests_and_responses::{decrypt_response, encrypt_and_sign_payload};

// product id: TestcVVS-zcVMKinnSw/NcioqdKUlTONp

#[allow(unused)]
pub async fn test_get_license(req_client: &reqwest::Client, server_keys: (ExpiringEcdhKey, ExpiringEcdsaKey)) -> Result<(), Error> {
    let inner_payload = generate_get_license_payload();
    let payload = encrypt_and_sign_payload(inner_payload, false, server_keys);
    let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/get_license_refactor")
        .header("X-Signature", payload.signature.to_base64())
        .body(payload.encrypted)
        .send()
        .await.unwrap();
    let license_data = get_license_data(response, payload.symmetric_key).await;
    println!("License data:\n{}", license_data);
    Ok(())
}

#[allow(unused)]
pub fn generate_get_license_payload() -> Vec<u8> {
    use protos::get_license_request::{GetLicenseRequest};
    let req = GetLicenseRequest {
        user_id: USER_ID.into()
    };
    req.encode_length_delimited_to_vec()
}

pub fn license_data_to_str(license_data: &GetLicenseResponse) -> String {
    let license_code = license_data.license_code.clone();
    let offline_code = license_data.offline_code.clone();
    let license_info = license_data.licensed_products.clone();
    
    let license_info: String = {
        let mut string = String::new();
        for (k, v) in license_info {
            string.push_str(&format!(
                "{{\n\t{}\n", k
            ));
            string.push_str(&format!("\t\tlicense_type: {},\n", v.license_type));
            string.push_str(&format!("\t\tmachine_limit: {},\n", v.machine_limit));
            string.push_str(&format!("\t\tmachine_count: {},\n", v.online_machines.len() + v.offline_machines.len()));
            string.push_str(&format!("\t\texpiration_or_renewal: {},\n", v.expiration_or_renewal));
            string.push_str(&format!("\t\tonline_machines: {:?},\n", v.online_machines));
            string.push_str(&format!("\t\toffline_machines: {:?}\n", v.offline_machines));
            string.push_str("},\n");
        }
        string
    };

    format!("License code: {}\nOffline code: {}\nLicense Info: {}", license_code, offline_code, license_info)
}
#[allow(unused)]
pub async fn get_license_data(response: Response, symmetric_key: Key) -> String {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::get_license_request::GetLicenseResponse;
    let r = GetLicenseResponse::decode_length_delimited(decrypted.as_slice()).unwrap();
    license_data_to_str(&r)
}