use std::time::Duration;
use std::time::Instant;
use create_product::generate_create_product_payload;
use create_product::get_product_id;
#[allow(unused)]
use crate::{
    create_license::test_create_license,
    create_product::test_create_product,
    register_store::test_register_store,
    get_license::test_get_license,
    license_activation::test_license_activation
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
mod get_license;
mod license_activation;
mod register_store;
mod server_requests_and_responses;

const GB_PER_MB: f64 = 0.0009765625;
const GB_S_BASE_COST: f64 = 0.0000133334;

fn calculate_costs(memsizes: &[usize], outcomes: Vec<Vec<u128>>) -> Vec<(u128, f64)> {
    let mut costs: Vec<(u128, f64)> = Vec::with_capacity(memsizes.len());
    for i in 0..memsizes.len() {
        let memory = memsizes[i];
        let mut sum = 0;
        for j in 0..outcomes[i].len() {
            sum += outcomes[i][j];
        }
        let average_time_ms = sum / outcomes[i].len() as u128;

        let average_time_s = average_time_ms / 1000;

        let memory_allocated = memory as f64 * GB_PER_MB;
        let total_compute_gb_s = memory_allocated * average_time_s as f64;

        let cost_per_million_invocations = GB_S_BASE_COST * total_compute_gb_s * 1_000_000f64;
        costs.push((average_time_ms, cost_per_million_invocations));
    }
    costs
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let req_client = reqwest::Client::new();
    let server_keys = get_server_pubkeys(&req_client).await;
    // test_register_store(&req_client, server_keys).await?;
    // test_create_product(&req_client, server_keys).await?;
    // test_create_license(&req_client, server_keys).await?;
    test_get_license(&req_client, server_keys).await?;
    //test_license_activation(&req_client, server_keys).await?;
    Ok(())
}

#[allow(unused)]
async fn power_tuning(req_client: &reqwest::Client) -> Result<(), Error> {
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let aws_config = aws_config::from_env().region(region_provider).load().await;
    let client = Client::new(&aws_config);
    let server_keys = get_server_pubkeys(&req_client).await;
    let memsizes = [128, 256, 384, 512, 650, 700, 750, 800, 850, 900];
    let iterations = 4;
    let mut outcomes = vec![vec![0u128; iterations]; memsizes.len()];
    //let mut store_id: String = String::new();
    let mut product_id: String = String::new();
    for m in 0..memsizes.len() {
        client.update_function_configuration()
            .function_name("create_plugin_refactor")
            .set_memory_size(Some(memsizes[m] as i32))
            .send()
            .await.unwrap();
        sleep(Duration::from_millis(5000)).await;

        for i in 0..iterations {
            let inner_payload = generate_create_product_payload();
            let payload = encrypt_and_sign_payload(inner_payload, false, server_keys.clone());
            
            let start = Instant::now();
            let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/create_plugin_refactor")
            //let response = req_client.post("https://01lzc0nx9e.execute-api.us-east-1.amazonaws.com/v2/register_store_refactor")
                .header("X-Signature", payload.signature.to_base64())
                .body(payload.encrypted)
                .send()
                .await.unwrap();
            let end = Instant::now();
            outcomes[m][i] = end.duration_since(start).as_millis();

            product_id = get_product_id(response, payload.symmetric_key).await;
            //store_id = get_store_id(response, payload.symmetric_key).await;

            sleep(Duration::from_millis(1000)).await;
        }
    }

    println!("Register Store Outcomes:");
    let costs_per_memory_allocated = calculate_costs(&memsizes, outcomes);
    println!("Product ID: {}", product_id);
    //println!("Store ID: {}", store_id);
    for i in 0..costs_per_memory_allocated.len() {
        println!("With {} MB of RAM\n{} ms average time\n${} average cost", memsizes[i], costs_per_memory_allocated[i].0, costs_per_memory_allocated[i].1)
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use p384::ecdsa::{Signature, SigningKey, signature::Signer};
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