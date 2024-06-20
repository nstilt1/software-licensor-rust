//! A plugin creation API method for a licensing service.

use std::collections::HashMap;
use proto::protos::store_db_item::ProductInfo;
use utils::aws_config::meta::region::RegionProviderChain;
use utils::aws_sdk_dynamodb::types::{KeysAndAttributes, PutRequest, WriteRequest};
use utils::aws_sdk_dynamodb::Client;
use utils::dynamodb::maps::Maps;
use proto::protos::create_product_request::{CreateProductRequest, CreateProductResponse};
use utils::prelude::proto::protos::store_db_item::StoreDbItem;
use utils::tables::metrics::METRICS_TABLE;
use utils::{impl_function_handler, prelude::*};
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};

use http_private_key_manager::impl_handle_crypto;

impl_function_handler!(
    CreateProductRequest, 
    CreateProductResponse, 
    ApiError,
    false
);

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut CreateProductRequest, hasher: D, signature: Vec<u8>) -> Result<CreateProductResponse, ApiError> {
    debug_log!("In process_request()");
    if request.version.len() < 1 {
        return Err(ApiError::InvalidRequest("The version must be at least one number".into()))
    }

    // the StoreId has already been verified in `decrypt_and_hash_request()` but
    // we still need to verify the signature against the public key in the db
    let client = init_dynamodb_client!();
    debug_log!("Set client with aws_config");

    let mut store_item = AttributeValueHashMap::new();
    let store_id = key_manager.get_store_id()?;
    debug_log!("Got store_id");

    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
    store_item.insert_item(&STORES_TABLE.id, Blob::new(hashed_store_id.to_vec()));

    debug_log!("Checking if store id exists in DB");
    
    let mut request_items: HashMap<String, KeysAndAttributes> = HashMap::new();
    request_items.insert(
        STORES_TABLE.table_name.to_string(), 
        KeysAndAttributes::builder()
            .keys(store_item.clone())
            .consistent_read(false)
            .build()?
    );
    request_items.insert(
        METRICS_TABLE.table_name.to_string(),
        KeysAndAttributes::builder()
            .keys(store_item.clone())
            .consistent_read(false)
            .build()?
    );

    let batch_get_output = client.batch_get_item()
        .set_request_items(Some(request_items))
        .send()
        .await?;

    let tables = match batch_get_output.responses {
        Some(v) => v,
        None => return Err(ApiError::NotFound)
    };

    let mut metrics_item = if let Some(v) = tables.get(METRICS_TABLE.table_name) {
        if v.len() != 1 {
            store_item.clone()
        } else {
            v[0].clone()
        }
    } else {
        store_item.clone()
    };

    store_item = if let Some(v) = tables.get(STORES_TABLE.table_name) {
        if v.len() != 1 {
            return Err(ApiError::NotFound)
        } else {
            v[0].clone()
        }
    } else {
        return Err(ApiError::NotFound)
    };
    
    debug_log!("Store ID was found in the DB");

    // verify signature with public key
    verify_signature(&store_item, hasher, &signature)?;

    debug_log!("Decrypting Store DB Proto");
    let mut store_proto: StoreDbItem = key_manager.decrypt_db_proto(
        &STORES_TABLE.table_name,
        store_id.binary_id.as_ref(),
        store_item.get_item(&STORES_TABLE.protobuf_data)?.as_ref()
    )?;

    match store_proto.product_ids.get_mut(&request.product_id_prefix) {
        Some(v) => {
            // update product_info
            v.is_offline_allowed = request.is_offline_allowed;
            v.version = request.version.clone();
            store_item.insert_item(
                &STORES_TABLE.protobuf_data,
                Blob::new(
                    key_manager.encrypt_db_proto(
                        &STORES_TABLE.table_name,
                        store_id.binary_id.as_ref(),
                        &store_proto
                    )?
                )
            );

            let product_id = key_manager.validate_product_id(&request.product_id_prefix, &store_id)?;
            
            client.put_item()
                .table_name(STORES_TABLE.table_name)
                .set_item(Some(store_item))
                .send()
                .await?;

            let resp = CreateProductResponse {
                product_id: request.product_id_prefix.to_owned(),
                product_public_key: key_manager.get_product_public_key(&product_id, &store_id),
            };
            return Ok(resp)
        },
        None => ()
    }

    // create plugin id and public key, and verify that it isn't already in the db
    let (product_id, product_pubkey) = loop {
        let (id, pubkey) = key_manager.generate_product_id(&request.product_id_prefix, &store_id)?;
        if !store_proto.product_ids.contains_key(&id.encoded_id) {
            break (id, pubkey)
        }
    };

    store_proto.product_ids.insert(product_id.encoded_id.clone(), ProductInfo {
        is_offline_allowed: request.is_offline_allowed,
        version: request.version.clone(),
        max_machines_per_license: request.max_machines_per_license,
    });

    debug_log!("Encrypting Stores DB Proto");
    store_item.insert_item(
        &STORES_TABLE.protobuf_data,
        Blob::new(key_manager.encrypt_db_proto(
            &STORES_TABLE.table_name, 
            store_id.binary_id.as_ref(), 
            &store_proto
        )?)
    );

    debug_log!("Creating request_items for a batch_write_item request");

    let mut request_items: HashMap<String, Vec<WriteRequest>> = HashMap::new();
    request_items.insert(STORES_TABLE.table_name.into(), vec![WriteRequest::builder()
        .put_request(PutRequest::builder()
            .set_item(Some(store_item))
            .build()?
        ).build()
    ]);

    debug_log!("Increasing num_products by 1");
    metrics_item.increase_number(&METRICS_TABLE.num_products, 1)?;

    request_items.insert(METRICS_TABLE.table_name.into(), vec![WriteRequest::builder()
        .put_request(PutRequest::builder()
            .set_item(Some(metrics_item))
            .build()?
        ).build()
    ]);

    debug_log!("performing batch_write_item operation");
    client.batch_write_item()
        .set_request_items(Some(request_items))
        .send()
        .await?;
    
    let response = CreateProductResponse {
        product_id: product_id.encoded_id,
        product_public_key: product_pubkey.to_vec(),
    };

    debug_log!("Success");
    Ok(response)
}