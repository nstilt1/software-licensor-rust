use proto::protos::pubkeys::{ExpiringEcdhKey, ExpiringEcdsaKey};
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use utils::prelude::proto::protos;
use utils::prelude::*;
use crate::get_license::get_license_data;
use crate::{Error, USER_ID};

use crate::server_requests_and_responses::encrypt_and_sign_payload;

#[allow(unused)]
pub async fn test_regenerate_license_code(req_client: &reqwest::Client, server_keys: (ExpiringEcdhKey, ExpiringEcdsaKey)) -> Result<(), Error> {
    let inner_payload = generate_regen_license_payload();
    let payload = encrypt_and_sign_payload(inner_payload, false, server_keys);
    let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/regenerate_license_code")
        .header("X-Signature", payload.signature.to_base64(false))
        .body(payload.encrypted)
        .send()
        .await.unwrap();

    let license_info = get_license_data(response, payload.symmetric_key).await;
    println!("Store ID: {}", license_info);
    Ok(())
}

#[allow(unused)]
pub fn generate_regen_license_payload() -> Vec<u8> {
    use protos::regenerate_license_code::RegenerateLicenseCodeRequest;
    let mut rng = ChaCha8Rng::from_seed([4u8; 32]);
    let signing_key = p384::ecdsa::SigningKey::random(&mut rng);
    let pubkey = signing_key.verifying_key().to_sec1_bytes();
    let result = RegenerateLicenseCodeRequest {
        user_id: USER_ID.into()
    };
    result.encode_length_delimited_to_vec()
}