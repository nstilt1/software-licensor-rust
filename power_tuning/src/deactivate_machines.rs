use proto::protos::pubkeys::{ExpiringEcdhKey, ExpiringEcdsaKey};
use rand_chacha::{ChaCha8Rng, rand_core::SeedableRng};
use utils::prelude::proto::protos;
use utils::prelude::*;
use crate::get_license::get_license_data;
use crate::{Error, USER_ID};

use crate::server_requests_and_responses::encrypt_and_sign_payload;

#[allow(unused)]
pub async fn test_deactivate_machines(req_client: &reqwest::Client, server_keys: (ExpiringEcdhKey, ExpiringEcdsaKey)) -> Result<(), Error> {
    let inner_payload = generate_deactivate_machines_payload();
    let payload = encrypt_and_sign_payload(inner_payload, false, server_keys);
    let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/deactivate_machines")
        .header("X-Signature", payload.signature.to_base64())
        .body(payload.encrypted)
        .send()
        .await.unwrap();

    let license_info = get_license_data(response, payload.symmetric_key).await;
    println!("Store ID: {}", license_info);
    Ok(())
}

#[allow(unused)]
pub fn generate_deactivate_machines_payload() -> Vec<u8> {
    use protos::deactivate_machines::DeactivateMachinesRequest;
    let mut rng = ChaCha8Rng::from_seed([4u8; 32]);
    let signing_key = p384::ecdsa::SigningKey::random(&mut rng);
    let pubkey = signing_key.verifying_key().to_sec1_bytes();
    let result = DeactivateMachinesRequest {
        machine_ids: vec!["machine_id_2".into(), "machine_id_1".into()],
        user_id: USER_ID.into()
    };
    result.encode_length_delimited_to_vec()
}