//! A get license API method for a licensing service.

use std::collections::HashMap;

use utils::aws_config::meta::region::RegionProviderChain;
use utils::aws_sdk_dynamodb::Client;
use utils::prelude::proto::protos::create_store_request::StoreDbItem;
use utils::prelude::proto::protos::fetch_product_info::{FetchProductInfoRequest, FetchProductInfoResponse, ProductInfo};
use utils::prelude::*;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, Body, Error, Request, RequestExt, Response};

impl_function_handler!(
    FetchProductInfoRequest, 
    FetchProductInfoResponse, 
    ApiError, 
    false
);

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, _request: &mut FetchProductInfoRequest, hasher: D, signature: Vec<u8>) -> Result<FetchProductInfoResponse, ApiError> {
    debug_log!("Inside process_request");
    // the StoreId has already been verified in `decrypt_and_hash_request()` but
    // we still need to verify the signature against the public key in the db
    let client = init_dynamodb_client!();
    
    let mut store_item = AttributeValueHashMap::new();
    let store_id = key_manager.get_store_id()?;
    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
    store_item.insert_item(&STORES_TABLE.id, Blob::new(hashed_store_id.to_vec()));

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

    let protobuf_data: StoreDbItem = key_manager.decrypt_db_proto(
        &STORES_TABLE.table_name, 
        store_id.binary_id.as_ref(), 
        store_item.get_item(&STORES_TABLE.protobuf_data)?.as_ref()
    )?;

    let mut error = None;

    let product_info: HashMap<String, ProductInfo> = protobuf_data.product_ids.clone().into_iter().map(|(key, value)| {
        let product_id = match key_manager.validate_product_id(&key, &store_id) {
            Ok(v) => v,
            Err(e) => {
                error_log!("product id was not valid; store id: {}\nproduct_id: {}", store_id.encoded_id, key);
                error = Some(e);
                key_manager.generate_product_id("ERROR", &store_id).expect("Should be valid").0
            }
        };
        (product_id.encoded_id.to_string(), ProductInfo {
            is_offline_allowed: value.is_offline_allowed,
            version: value.version.clone(),
            max_machines_per_license: value.max_machines_per_license,
            product_name: value.product_name.clone(),
            public_key: key_manager.get_product_public_key(&product_id, &store_id).to_base64(true),
        })
    }).collect();

    Ok(FetchProductInfoResponse {
        product_info,
    })
}