//! A plugin creation API method for a licensing service.

use std::collections::HashMap;
use proto::protos::store_db_item::ProductInfo;
use utils::aws_config::meta::region::RegionProviderChain;
use utils::aws_sdk_dynamodb::types::{KeysAndAttributes, PutRequest, WriteRequest};
use utils::aws_sdk_dynamodb::Client;
use utils::crypto::p384::ecdsa::Signature;
use utils::dynamodb::maps::Maps;
use proto::protos::{
    product_db_item::ProductDbItem,
    create_product_request::{CreateProductRequest, CreateProductResponse},
};
use utils::prelude::proto::protos::store_db_item::StoreDbItem;
use utils::tables::metrics::METRICS_TABLE;
use utils::{impl_function_handler, prelude::*};
use utils::tables::products::PRODUCTS_TABLE;
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
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let aws_config = utils::aws_config::from_env().region(region_provider).load().await;
    let client = Client::new(&aws_config);
    debug_log!("Set client with aws_config");

    let mut store_item = AttributeValueHashMap::new();
    let store_id = key_manager.get_store_id()?;
    debug_log!("Got store_id");

    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
    store_item.insert_item(STORES_TABLE.id, Blob::new(hashed_store_id.to_vec()));

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

    let public_key = store_item.get_item(STORES_TABLE.public_key)?;
    debug_log!("Got public key");
    // verify signature with public key
    let pubkey = PublicKey::from_sec1_bytes(&public_key.as_ref())?;
    debug_log!("Set pubkey");
    let verifier = VerifyingKey::from(pubkey);
    let signature: Signature = Signature::from_bytes(signature.as_slice().try_into().unwrap())?;
    debug_log!("Set signature");
    verifier.verify_digest(hasher, &signature)?;
    debug_log!("Verified signature");
    // signature verified
    // create plugin id and public key, and verify that it isn't already in the db
    let mut product_item = AttributeValueHashMap::new();
    
    debug_log!("Checking for an unused product_id");
    let (product_id, product_pubkey) = loop {
        let (p_id, p_pk) = key_manager.generate_product_id(&request.product_id_prefix, &store_id)?;
        // hash plugin id before inserting it into table
        let hashed_product_id = salty_hash(&[p_id.binary_id.as_ref()], &PRODUCT_DB_SALT);
        product_item.insert_item(PRODUCTS_TABLE.id, Blob::new(hashed_product_id.to_vec()));
        
        // with a 48-byte, mostly random ID, it is extremely improbable 
        // that it already exists in the DB, and there's an even smaller 
        // chance that it was added to the DB in the last 10 seconds, so
        // might as well do an eventually consistent read... but maybe 
        // it shouldn't be done at all
        let get_output = client.get_item()
            .table_name(PRODUCTS_TABLE.table_name)
            .set_key(Some(product_item.clone()))
            .consistent_read(false)
            .send()
            .await?;

        if get_output.item.is_none() {
            break (p_id, p_pk);
        }
    };

    debug_log!("found a valid product id");

    // fill the product item with data
    let product_protobuf = ProductDbItem {
        version: request.version.to_owned(),
        store_id: store_id.binary_id.as_ref().into(),
        product_id: product_id.binary_id.as_ref().into(),
        product_name: request.product_name.to_owned(),
    };

    product_item.insert_item(
        PRODUCTS_TABLE.hashed_store_id, 
        Blob::new(salty_hash(&[store_id.binary_id.as_ref()], &PRODUCT_DB_SALT).to_vec())
    );

    product_item.insert_item(PRODUCTS_TABLE.is_offline_allowed, request.is_offline_allowed);
    product_item.insert_item(PRODUCTS_TABLE.max_machines_per_license, request.max_machines_per_license.to_string());

    product_item.insert_item_into(PRODUCTS_TABLE.num_machines_total, "0");
    product_item.insert_item_into(PRODUCTS_TABLE.num_licenses_total, "0");
    product_item.insert_item_into(PRODUCTS_TABLE.num_offline_machines, "0");
    product_item.insert_item_into(PRODUCTS_TABLE.num_subscription_machines, "0");
    product_item.insert_item_into(PRODUCTS_TABLE.num_perpetual_machines, "0");
    product_item.insert_item_into(PRODUCTS_TABLE.num_license_auths, "0");
    
    debug_log!("Encrypting the .proto for going into the DB");
    let encrypted_protobuf = key_manager.encrypt_db_proto(
        PRODUCTS_TABLE.table_name, 
        &product_id.binary_id.as_ref(), 
        &product_protobuf
    )?;
    product_item.insert_item(PRODUCTS_TABLE.protobuf_data, Blob::new(encrypted_protobuf));

    debug_log!("Increasing num_products by 1");

    debug_log!("Decrypting Store DB Proto");
    let mut store_proto: StoreDbItem = key_manager.decrypt_db_proto(
        &STORES_TABLE.table_name,
        store_id.binary_id.as_ref(),
        store_item.get_item(STORES_TABLE.protobuf_data)?.as_ref()
    )?;
    store_proto.product_ids.insert(product_id.encoded_id.clone(), ProductInfo {
        is_offline_allowed: request.is_offline_allowed,
        version: request.version.clone(),
    });
    debug_log!("Encrypting Stores DB Proto");
    store_item.insert_item(
        STORES_TABLE.protobuf_data,
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

    request_items.insert(PRODUCTS_TABLE.table_name.into(), vec![WriteRequest::builder()
        .put_request(PutRequest::builder()
            .set_item(Some(product_item))
            .build()?
        ).build()
    ]);

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