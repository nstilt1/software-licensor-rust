//! A get license API method for a licensing service.

use utils::aws_config::meta::region::RegionProviderChain;
use utils::aws_sdk_dynamodb::Client;
use utils::get_license::{construct_get_license_response_from_license_item, query_dynamodb_for_license_item_primary_key};
use utils::prelude::proto::protos::get_license_request::{GetLicenseRequest, GetLicenseResponse};
use utils::prelude::*;
use utils::tables::licenses::LICENSES_TABLE;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};

impl_function_handler!(
    GetLicenseRequest, 
    GetLicenseResponse, 
    ApiError, 
    false
);

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut GetLicenseRequest, hasher: D, signature: Vec<u8>) -> Result<GetLicenseResponse, ApiError> {
    debug_log!("Inside process_request");
    // the StoreId has already been verified in `decrypt_and_hash_request()` but
    // we still need to verify the signature against the public key in the db
    let client = init_dynamodb_client!();
    
    let mut store_item = AttributeValueHashMap::new();
    let store_id = key_manager.get_store_id()?;
    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
    store_item.insert_item(STORES_TABLE.id, Blob::new(hashed_store_id.to_vec()));

    let get_output = client.get_item()
        .table_name(STORES_TABLE.table_name)
        .set_key(Some(store_item))
        .consistent_read(false)
        .send()
        .await?;
    
    store_item = match get_output.item {
        Some(x) => x,
        // It is very unlikely that this will happen, unless the salt used for 
        // hashing were to change... in which case, it would happen every time
        None => return Err(ApiError::NotFound)
    };
    
    // verify signature with public key
    verify_signature(&store_item, hasher, &signature)?;

    // signature verified
    // get license item from db
    let mut license_item = query_dynamodb_for_license_item_primary_key(&client, &store_id, &request.user_id).await?;

    let get_output = client.get_item()
        .table_name(LICENSES_TABLE.table_name)
        .set_key(Some(license_item))
        .consistent_read(false)
        .send()
        .await?;
    
    license_item = match get_output.item {
        Some(x) => x,
        None => return Err(ApiError::NotFound)
    };
    
    construct_get_license_response_from_license_item(key_manager, &license_item)
}