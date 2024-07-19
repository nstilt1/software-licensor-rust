use reqwest::Response;
use utils::crypto::chacha20poly1305::Key;

#[allow(unused)]
use utils::{
    base64::Base64Vec, 
    prelude::proto::{
        prost::Message, 
        protos::{
            self, 
            create_license_request::{
                product_info::LicenseType, 
                PerpetualLicense, 
                TrialLicense,
                SubscriptionLicense
            }, 
            get_license_request::GetLicenseResponse,
            pubkeys::{
                ExpiringEcdhKey, 
                ExpiringEcdsaKey
            }
        }
    }
};
use std::collections::HashMap;
use crate::{get_license::license_data_to_str, server_requests_and_responses::decrypt_response, Error, USER_ID};
use crate::server_requests_and_responses::encrypt_and_sign_payload;

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

    let license_code = parse_create_license_response(response, payload.symmetric_key).await;
    println!("License code: {}", license_code);
    Ok(())
}

#[allow(unused)]
pub async fn parse_create_license_response(response: Response, symmetric_key: Key) -> String {
    let decrypted = decrypt_response(response, symmetric_key).await;
    use protos::create_license_request::CreateLicenseResponse;
    let r = CreateLicenseResponse::decode_length_delimited(decrypted.as_slice()).unwrap();
    let license_data = GetLicenseResponse::decode_length_delimited(r.license_info.as_slice()).unwrap();
    let str = license_data_to_str(&license_data);
    format!("Issues: {:?}\nlicense data: {}", r.issues, str)
}

#[allow(unused)]
pub fn generate_create_license_payload() -> Vec<u8> {
    use protos::create_license_request::{CreateLicenseRequest, ProductInfo};
    let mut product_info: HashMap<String, ProductInfo> = HashMap::new();
    // product_info.insert("Test1U58-dmYcq_corvrg5ca19az_Lzef".into(), ProductInfo {
    //     license_type: "perpetual".into(),
    //     quantity: 1,
    //     subtotal: "0".into()
    // });
    product_info.insert(
        "TestCq16-Ozuwedx/Dda_ILA4wGzTNzTJ".into(), 
        ProductInfo {
            license_type: Some(
                LicenseType::PerpetualLicense(
                    PerpetualLicense {
                        quantity: 1,
                    }
                )
            ),
        }
    );
    // product_info.insert("TestCq16-ClKZsVOLN_zFnR9y4EWS4z9o".into(), ProductInfo {
    //     license_type: "trial".into(),
    //     quantity: 1,
    //     subtotal: "0".into()
    // });
    // product_info.insert("TestGhDt-jkezEw0aV8L1Pn/bgrpz5gog".into(), ProductInfo {
    //     license_type: "subscription".into(),
    //     quantity: 1,
    //     subtotal: "0".into(),
    // });
    // product_info.insert("TestLuQH-gmCT0_JXH3yxjSC2D2mPHtNq".into(), ProductInfo {
    //     license_type: Some(LicenseType::PerpetualLicense(PerpetualLicense {
    //         subtotal: 0,
    //         quantity: 1,
    //     })),
    // });
    let req = CreateLicenseRequest {
        customer_first_name: "Test".into(),
        customer_last_name: "TestLastName".into(),
        customer_email: "test@m.com".into(),
        order_id: "Test Order ID".into(),
        user_id: USER_ID.into(),
        custom_success_message: "".into(),
        product_info,
    };
    req.encode_length_delimited_to_vec()
}