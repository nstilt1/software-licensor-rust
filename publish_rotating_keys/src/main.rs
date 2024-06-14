use aws_lambda_events::event::eventbridge::EventBridgeEvent;
use utils::{
    aws_config::{
        self, meta::region::RegionProviderChain
    }, 
    aws_sdk_s3::{
        primitives::ByteStream, 
        Client
    }, 
    prelude::*, 
    serde_json::{
        json, 
        Value
    }
};
use utils::lambda_runtime;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use utils::{
    crypto::http_private_key_manager::prelude::{
        months_to_seconds, 
        years_to_seconds
    }, 
    now_as_seconds, 
};
use proto::protos::pubkeys::{ExpiringEcdhKey, ExpiringEcdsaKey, PubkeyRepo};
/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
/// - https://github.com/aws-samples/serverless-rust-demo/
async fn function_handler(_event: LambdaEvent<EventBridgeEvent>) -> Result<Value, Error> {
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let config = aws_config::from_env().region(region_provider).load().await;
    let s3_client = Client::new(&config);

    let mut key_manager = init_key_manager(None, None);
    let num_ecdh_keys = 32;
    let expiration_for_ephemeral_keys = now_as_seconds() + months_to_seconds(2);
    let ecdh_keys = key_manager.generate_ecdh_pubkeys_and_ids(
        num_ecdh_keys, 
        Some(expiration_for_ephemeral_keys)
    ).unwrap();
    
    let mut pubkey_repo = PubkeyRepo {
        ecdh_keys: Vec::with_capacity(num_ecdh_keys),
        ecdsa_key: None,
    };
    for (id, key) in ecdh_keys.iter() {
        pubkey_repo.ecdh_keys.push(
            ExpiringEcdhKey {
                ecdh_key_id: id.as_ref().to_vec(),
                ecdh_public_key: key.to_sec1_bytes().to_vec(),
            }
        )
    }

    let expiration = now_as_seconds() + years_to_seconds(1);
    let ecdsa_key = key_manager
        .generate_ecdsa_key_and_id::<EcdsaAlg, EcdsaKeyId>(
            "",
            Some(expiration),
            None
        ).expect("This should work");
    pubkey_repo.ecdsa_key = Some(ExpiringEcdsaKey {
        ecdsa_key_id: ecdsa_key.0.binary_id.as_ref().to_vec(),
        ecdsa_public_key: ecdsa_key.1.verifying_key().to_sec1_bytes().to_vec(),
        expiration
    });

    s3_client.put_object()
        .bucket(std::env::var("PUBKEY_BUCKET").expect("missing PUBKEY_BUCKET env"))
        .key("public_keys")
        .body(ByteStream::from(pubkey_repo.encode_length_delimited_to_vec()))
        .send()
        .await?;
    Ok(json!({ "message": "Pubkeys written successfully"}))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let func = service_fn(function_handler);
    lambda_runtime::run(func).await
}
