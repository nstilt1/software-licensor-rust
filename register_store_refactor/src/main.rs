//! A store registration API method for a licensing service.
use std::str::FromStr;
use proto::protos::register_store_request::register_store_request::PublicSigningKey;

use utils::prelude::*;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use proto::protos::register_store_request::{RegisterStoreRequest, RegisterStoreResponse};
use utils::aws_sdk_dynamodb::Client;
use utils::aws_config::meta::region::RegionProviderChain;

impl_function_handler!(
    RegisterStoreRequest, 
    RegisterStoreResponse, 
    ApiError, 
    false
);

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut RegisterStoreRequest, hasher: D, signature: Vec<u8>) -> Result<RegisterStoreResponse, ApiError> {
    debug_log!("In process_request");

    let client = init_dynamodb_client!();

    debug_log!("Made it past initial validation");
    
    // verify public key before storing info in the database to ensure that 
    // they/we know how to format requests and that everything is working 
    // properly
    
    // convert PEM to DER
    let public_signing_key_der = match &request.public_signing_key {
        Some(value) => match value {
            PublicSigningKey::Pem(v) => {
                let pubkey: PublicKey = PublicKey::from_str(v.as_str())?;
                request.public_signing_key = Some(PublicSigningKey::Der(pubkey.to_sec1_bytes().to_vec()));
                pubkey.to_sec1_bytes().to_vec()
            }, PublicSigningKey::Der(v) => v.clone(),
        },
        None => return Err(ApiError::InvalidRequest("The public signing key must be either PEM or DER encoded.".into()))
    };

    verify_signature(request, hasher, &signature)?;

    debug_log!("Verfied signature");

    // generate store ID and make sure it isn't already in the database
    let store_id = key_manager.get_store_id()?;
    debug_log!("Got the store ID");

    let mut store_item = AttributeValueHashMap::new();

    let hashed_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
    
    store_item.insert_item(&STORES_TABLE.id, Blob::new(hashed_id.to_vec()));
    
    let get_output = client.get_item()
        .table_name(STORES_TABLE.table_name)
        .consistent_read(false)
        .set_key(Some(store_item.clone()))
        .send()
        .await?;

    if get_output.item.is_none() {
        debug_log!("Could not find Store with given ID");
        return Err(ApiError::NotFound);
    }

    debug_log!("Found store via ID");

    store_item = get_output.item.unwrap();

    if store_item.get_item(&STORES_TABLE.public_key).expect("should be populated").as_ref().len() != 0 {
        error_log!("The store has already been registered. Public key: {:?}", store_item.get_item(&STORES_TABLE.public_key).unwrap().as_ref());
        return Err(ApiError::StoreAlreadyRegistered);
    }

    store_item.insert_item(&STORES_TABLE.public_key, Blob::new(public_signing_key_der));

    debug_log!("Picked a store ID");
    
    // a solid store_id has been found, most likely with one try. Now, we
    // will create the database item

    client.put_item()
        .table_name(STORES_TABLE.table_name)
        .set_item(Some(store_item))
        .send()
        .await?;
    
    debug_log!("Put store item in database");
    
    let response = RegisterStoreResponse {
        store_id: store_id.encoded_id,
    };
    Ok(response)
}