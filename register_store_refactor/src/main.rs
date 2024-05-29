//! A store registration API method for a licensing service.
use utils::crypto::p384::ecdsa::Signature;
use utils::crypto::sha2::Sha384;
use utils::{debug_log, error_log, now_as_seconds};
use std::time::{SystemTime, UNIX_EPOCH};
use proto::protos::store_db_item::StoreDbItem;
use utils::aws_sdk_s3::primitives::Blob;
use utils::prelude::proto::protos::store_db_item;
use utils::prelude::*;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use proto::protos::register_store_request::{RegisterStoreRequest, RegisterStoreResponse};
use proto::prost::Message;
use http_private_key_manager::Request as RestRequest;
use utils::aws_sdk_dynamodb::Client;
use utils::aws_config::meta::region::RegionProviderChain;

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut RegisterStoreRequest, hasher: D, signature: Vec<u8>) -> Result<RegisterStoreResponse, ApiError> {
    debug_log!("In process_request");
    if request.contact_first_name.len() < 2 || 
        request.contact_last_name.len() < 2 ||
        request.store_name.len() < 1 ||
        request.store_url.len() < 2 || 
        request.state.len() < 2 ||
        request.country.len() < 2 
    {
        return Err(ApiError::InvalidRequest("Please provide accurate information".into()))
    }

    debug_log!("Made it past initial validation");
    // verify public key before storing info in the database to ensure that they know how to format requests and that everything is working properly
    // with an established client, we will need to fetch the public key 
    // from the database to verify the signature instead of this
    let pubkey = PublicKey::from_sec1_bytes(&request.public_signing_key)?;
    debug_log!("Initialized pubkey");
    let verifier = VerifyingKey::from(pubkey);
    let signature: Signature = Signature::from_bytes(signature.as_slice().try_into().unwrap())?;
    debug_log!("Initialized signature");
    verifier.verify_digest(hasher, &signature)?;

    debug_log!("Verfied signature");

    // generate store ID and make sure it isn't already in the database
    let mut store_id = key_manager.get_store_id()?;
    debug_log!("Got the store ID");

    let mut store_item = AttributeValueHashMap::new();

    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    debug_log!("Set region_provider");
    let aws_config = utils::aws_config::from_env().region(region_provider).load().await;
    debug_log!("Set aws_config");
    let client = Client::new(&aws_config);

    debug_log!("Initialized dynamodb client");
    loop {
        let hashed_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
        
        store_item.insert_item(STORES_TABLE.id, Blob::new(hashed_id.to_vec()));
        
        let get_output = client.get_item()
            .table_name(STORES_TABLE.table_name)
            .consistent_read(false)
            .set_key(Some(store_item.clone()))
            .send()
            .await?;

        if get_output.item.is_some() {
            store_id = key_manager.regenerate_store_id()?;
        } else {
            break;
        }
    }
    debug_log!("Picked a store ID");
    
    // a solid store_id has been found, most likely with one try. Now, we
    // will create the database item
    let configs = if let Some(c) = &request.configs {
        // validate configs with bounds
        let mut c = c.clone();
        macro_rules! bound {
            ($value:expr, $lower_bound:literal) => {
                $value = $value.max($lower_bound)
            };
        }
        bound!(c.max_machines_per_license, 3);
        bound!(c.offline_license_frequency_hours, 300);
        bound!(c.perpetual_license_expiration_days, 24);
        bound!(c.perpetual_license_frequency_hours, 300);
        bound!(c.subscription_license_expiration_days, 30);
        bound!(c.subscription_license_expiration_leniency_hours, 6);
        bound!(c.subscription_license_frequency_hours, 16);
        bound!(c.trial_license_expiration_days, 3);
        bound!(c.trial_license_frequency_hours, 72);
        c
    } else {
        return Err(ApiError::InvalidRequest("Configs are required".into()))
    };

    let proto = StoreDbItem {
        contact_first_name: request.contact_first_name.to_owned(),
        contact_last_name: request.contact_last_name.to_owned(),
        store_name: request.store_name.to_owned(),
        store_url: request.store_url.to_owned(),
        email: request.contact_email.to_owned(),
        discord_username: request.discord_username.to_owned(),
        state: request.state.to_owned(),
        country: request.country.to_owned(),
        product_ids: Vec::new(),
        configs: Some(store_db_item::Configs {
            offline_license_frequency_hours: configs.offline_license_frequency_hours,
            perpetual_license_expiration_days: configs.perpetual_license_expiration_days,
            perpetual_license_frequency_hours: configs.perpetual_license_frequency_hours,
            subscription_license_expiration_days: configs.subscription_license_expiration_days,
            subscription_license_expiration_leniency_hours: configs.subscription_license_expiration_leniency_hours,
            subscription_license_frequency_hours: configs.subscription_license_frequency_hours,
            trial_license_expiration_days: configs.trial_license_expiration_days,
            trial_license_frequency_hours: configs.trial_license_frequency_hours,
        })
    };
    
    let encrypted_protobuf = key_manager.encrypt_db_proto(STORES_TABLE.table_name, store_id.binary_id.as_ref(), &proto)?;
    debug_log!("Encrypted store db item");
    store_item.insert_item(STORES_TABLE.protobuf_data, Blob::new(encrypted_protobuf));

    store_item.insert_item(STORES_TABLE.public_key, Blob::new(request.public_signing_key.to_vec()));
    store_item.insert_item(STORES_TABLE.registration_date, now_as_seconds().to_string());

    store_item.insert_item_into(STORES_TABLE.num_products, "0");
    store_item.insert_item_into(STORES_TABLE.num_licenses, "0");
    store_item.insert_item_into(STORES_TABLE.num_auths, "0");
    store_item.insert_item_into(STORES_TABLE.num_license_regens, "0");

    client.put_item()
        .table_name(STORES_TABLE.table_name)
        .set_item(Some(store_item))
        .send()
        .await?;
    
    debug_log!("Put store item in database");
    
    let response = RegisterStoreResponse {
        store_id: store_id.encoded_id,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    };
    Ok(response)
}
/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    debug_log!("In function_handler()");
    // Extract some useful information from the request
    if event.query_string_parameters_ref().is_some() {
        return ApiError::InvalidRequest("There should be no query string parameters.".into()).respond();
    }
    let signature = if let Some(s) = event.headers().get("X-Signature") {
        s.as_bytes().from_base64()?
    } else {
        return Err(Box::new(ApiError::InvalidRequest("Signature must be base64 encoded in the X-Signature header".into())))
    };
    let (mut request, req_bytes) = if let Body::Binary(contents) = event.body() {
        (RestRequest::decode_length_delimited(contents.as_slice())?, contents)
    } else {
        return ApiError::InvalidRequest("Body is not binary".into()).respond()
    };

    debug_log!("About to init key_manager");

    let mut key_manager = init_key_manager(None, None);
    debug_log!("Initialized key_manager");

    let chosen_symm_algo = request.symmetric_algorithm.to_lowercase();

    let (encrypted, signature) = match chosen_symm_algo.as_str() {
        "chacha20poly1305" => {
            let (mut decrypted, hash) = {
                debug_log!("In chacha20poly1305 segment");
                let result = key_manager.decrypt_and_hash_request::<ChaCha20Poly1305, Sha384, RegisterStoreRequest>(&mut request, req_bytes, true);
                debug_log!("Got result in chacha20poly1305 segment");
                if result.is_err() {
                    debug_log!("Result was an error");
                    error_log!("Error: {}", result.unwrap_err().to_string());
                    panic!()
                }
                result.unwrap()
            };
            debug_log!("Sending result to process_request()");
            let mut response = process_request(&mut key_manager, &mut decrypted, hash, signature).await?;
            debug_log!("Encrypting and signing the response");
            key_manager.encrypt_and_sign_response::<ChaCha20Poly1305, RegisterStoreResponse>(&mut response)?
        },
        "aes-gcm-128" => {
            debug_log!("In aes-gcm-128 segment");
            let (mut decrypted, hash) = key_manager.decrypt_and_hash_request::<Aes128Gcm, Sha384, RegisterStoreRequest>(&mut request, req_bytes, true)?;
            let mut response = process_request(&mut key_manager, &mut decrypted, hash, signature).await?;
            key_manager.encrypt_and_sign_response::<Aes128Gcm, RegisterStoreResponse>(&mut response)?
        },
        "aes-gcm-256" => {
            debug_log!("In aes-gcm-256 segment");
            let (mut decrypted, hash) = key_manager.decrypt_and_hash_request::<Aes256Gcm, Sha384, RegisterStoreRequest>(&mut request, req_bytes, true)?;
            let mut response = process_request(&mut key_manager, &mut decrypted, hash, signature).await?;
            key_manager.encrypt_and_sign_response::<Aes256Gcm, RegisterStoreResponse>(&mut response)?
        }
        _ => {
            debug_log!("Invalid symmetric encryption algorithm error");
            return Err(Box::new(ApiError::InvalidRequest("Invalid symmetric encryption algorithm".into())))
        }
    };
    debug_log!("Processed the request");

    // package `encrypted` into a response and `signature` into the header

    // Return something that implements IntoResponse.
    // It will be serialized to the right response event automatically by the runtime

    let resp = Response::builder()
        .status(200)
        .header("content-type", "application/x-protobuf")
        .header("X-Signature-Info", "Algorithm: Sha2-384 + NIST-P384")
        .header("X-Signature", signature.to_bytes().as_slice().to_base64())
        .body(encrypted.encode_length_delimited_to_vec().into())
        .map_err(Box::new)?;

    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_level(true)
        .with_max_level(tracing::Level::DEBUG)
        .init();
    debug_log!("In main()");
    run(service_fn(function_handler)).await
}
