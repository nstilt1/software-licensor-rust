use std::time::Duration;
use std::time::Instant;
use create_license::generate_create_license_payload;
use get_license::generate_get_license_payload;
use license_activation::generate_license_activation_payload;
use proto::protos::pubkeys::{ExpiringEcdhKey, ExpiringEcdsaKey};
use create_product::generate_create_product_payload;
use power_tuning::calculate_costs;
use register_store::generate_register_store_payload;
#[allow(unused)]
use crate::{
    create_license::test_create_license,
    create_product::test_create_product,
    register_store::test_register_store,
    get_license::test_get_license,
    license_activation::test_license_activation,
    deactivate_machines::test_deactivate_machines,
    regenerate_license_code::test_regenerate_license_code,
};
use server_requests_and_responses::encrypt_and_sign_payload;
use server_requests_and_responses::get_server_pubkeys;
use utils::aws_sdk_lambda;
use utils::aws_config;
pub use aws_sdk_lambda::{Client, Error};
use aws_config::meta::region::RegionProviderChain;
use utils::prelude::tokio::time::sleep;
use utils::prelude::*;

mod create_license;
mod create_product;
mod deactivate_machines;
mod get_license;
mod license_activation;
mod regenerate_license_code;
mod register_store;
mod power_tuning;
mod server_requests_and_responses;

impl_power_tuning!(register_store_power_tuning, "register_store_refactor", generate_register_store_payload, true, "https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/register_store_refactor");

impl_power_tuning!(create_plugin_power_tuning, "create_plugin_refactor", generate_create_product_payload, false, "https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/create_plugin_refactor");

impl_power_tuning!(create_license_power_tuning, "create_license_refactor", generate_create_license_payload, false, "https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/create_license_refactor");

impl_power_tuning!(get_license_power_tuning, "get_license_refactor", generate_get_license_payload, false, "https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/get_license_refactor");

impl_power_tuning!(license_activation_power_tuning, "license_activation_refactor", generate_license_activation_payload, false, "https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/license_activation_refactor");

pub const USER_ID: &str = "test_user_3";
pub const LICENSE_CODE: &str = "E7F0-42CD-8330-C891-B6D1";

#[tokio::main]
async fn main() -> Result<(), Error> {
    let req_client = reqwest::Client::new();
    let server_keys = get_server_pubkeys(&req_client).await;

    // tests
    //test_register_store(&req_client, server_keys).await?;
    test_create_product(&req_client, server_keys).await?;
    //test_create_license(&req_client, server_keys).await?;
    //test_get_license(&req_client, server_keys).await?;
    //test_license_activation(&req_client, server_keys).await?;
    //test_deactivate_machines(&req_client, server_keys).await?;
    //test_regenerate_license_code(&req_client, server_keys).await?;

    // power tuning
    //register_store_power_tuning(&req_client, server_keys).await?;
    //license_activation_power_tuning(&req_client, server_keys).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use p384::ecdsa::{SigningKey, signature::Signer};
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
    use utils::crypto::p384::ecdsa::signature::Verifier;

    #[test]
    fn signing_and_verifying_roundtrip() {
        let mut rng = ChaCha8Rng::from_seed([4u8; 32]);
        let signing_key = SigningKey::random(&mut rng);
        let data = b"testing roundtrip";
        let signature: Signature = signing_key.sign(data.as_slice());
        let encoded_signature = signature.to_vec();
        
        // verification
        let v_signature: Signature = Signature::from_bytes(encoded_signature.as_slice().try_into().unwrap()).unwrap();

        let verifying_key_bytes = signing_key.verifying_key().to_sec1_bytes();
        let verifying_key = VerifyingKey::from(PublicKey::from_sec1_bytes(&verifying_key_bytes).unwrap());
        assert!(verifying_key.verify(data.as_slice(), &v_signature).is_ok());
    }
}