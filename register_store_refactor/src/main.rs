//! A store registration API method for a licensing service.

use std::time::{SystemTime, UNIX_EPOCH};
use proto::protos::store_db_item::StoreDbItem;
use utils::prelude::proto::protos::store_db_item;
use utils::prelude::*;
use utils::tables::stores::STORES_TABLE;
use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDbClient, DynamoDb, GetItemInput, PutItemInput};
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use proto::protos::{register_store_request::RegisterStoreRequest, register_store_response::RegisterStoreResponse};
use proto::prost::Message;
use http_private_key_manager::Request as RestRequest;

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut RegisterStoreRequest, hasher: D, signature: Vec<u8>) -> Result<RegisterStoreResponse, ApiError> {
    if request.contact_first_name.len() < 2 || 
        request.contact_last_name.len() < 2 ||
        request.store_name.len() < 1 ||
        request.store_url.len() < 2 || 
        request.state.len() < 2 ||
        request.country.len() < 2 
    {
        return Err(ApiError::InvalidRequest("Please provide accurate information".into()))
    }
    if request.timestamp < SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 60 {
        return Err(ApiError::InvalidRequest("Timestamp is too old".into()))
    }
    // verify public key before storing info in the database to ensure that they know how to format requests and that everything is working properly
    // with an established client, we will need to fetch the public key 
    // from the database to verify the signature instead of this
    let pubkey = PublicKey::from_sec1_bytes(&request.public_signing_key)?;
    let verifier = VerifyingKey::from(pubkey);
    let signature = DerSignature::try_from(signature.as_slice())?;
    verifier.verify_digest(hasher, &signature)?;

    // generate store ID and make sure it isn't already in the database
    let mut store_id = key_manager.get_store_id()?;

    let mut store_item = AttributeValueHashMap::new();
    let client = DynamoDbClient::new(Region::UsEast1);

    loop {
        let hashed_id = salty_hash(&[store_id.binary_id.as_ref()], STORE_DB_SALT);
        
        store_item.insert_item_into(STORES_TABLE.id, hashed_id.to_vec());
        
        let get_output = &client.get_item(
            GetItemInput {
                table_name: STORES_TABLE.table_name.to_owned(),
                key: store_item.to_owned(),
                consistent_read: Some(true),
                ..Default::default()
            }
        ).await?;

        if get_output.item.is_some() {
            store_id = key_manager.regenerate_store_id()?;
        } else {
            break;
        }
    }
    
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
    store_item.insert_item_into(STORES_TABLE.protobuf_data, encrypted_protobuf);

    store_item.insert_item_into(STORES_TABLE.public_key, request.public_signing_key.clone());
    store_item.insert_item(STORES_TABLE.registration_date, request.timestamp.to_string());

    store_item.insert_item_into(STORES_TABLE.num_products, "0");
    store_item.insert_item_into(STORES_TABLE.num_licenses, "0");
    store_item.insert_item_into(STORES_TABLE.num_auths, "0");
    store_item.insert_item_into(STORES_TABLE.num_license_regens, "0");

    let put_input = PutItemInput {
        table_name: STORES_TABLE.table_name.to_owned(),
        item: store_item,
        ..Default::default()
    };
    client.put_item(put_input).await?;

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
        (RestRequest::decode(contents.as_slice())?, contents)
    } else {
        return ApiError::InvalidRequest("Body is not binary".into()).respond()
    };

    let mut key_manager = init_key_manager(None, None);

    let chosen_symm_algo = request.symmetric_algorithm.to_lowercase();
    let (encrypted, signature) = process_request_with_symmetric_algorithm!(
        key_manager, 
        process_request,
        &mut request,
        req_bytes,
        RegisterStoreRequest,
        RegisterStoreResponse,
        sha2::Sha384,
        signature,
        chosen_symm_algo.as_str(),
        true,                     // is_handshake    
        // the following values allow the client to choose the symmetric encryption algorithm via the `symmetric_algorithm` field in the request's protobuf message
        ("chacha20poly1305", ChaCha20Poly1305),
        ("aes-gcm-128", Aes128Gcm),
        ("aes-gcm-siv-128", Aes128GcmSiv),
        ("aes-gcm-256", Aes256Gcm),
        ("aes-gcm-siv-256", Aes256GcmSiv)
    );

    // package `encrypted` into a response and `signature` into the header

    // Return something that implements IntoResponse.
    // It will be serialized to the right response event automatically by the runtime

    let resp = Response::builder()
        .status(200)
        .header("content-type", "application/x-protobuf")
        .header("X-Signature-Info", "Algorithm: Sha2-384 + NIST-P384")
        .header("X-Signature", signature.to_bytes().as_slice().to_base64())
        .body(encrypted.encode_to_vec().into())
        .map_err(Box::new)?;

    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}
