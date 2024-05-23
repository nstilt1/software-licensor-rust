//! A plugin creation API method for a licensing service.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use utils::dynamodb::maps::Maps;
use proto::protos::{
    product_db_item::ProductDbItem,
    create_product_request::{CreateProductRequest, CreateProductResponse},
};
use utils::prelude::*;
use utils::tables::products::PRODUCTS_TABLE;
use utils::tables::stores::STORES_TABLE;
use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDbClient, DynamoDb, GetItemInput, BatchWriteItemInput, PutRequest, WriteRequest};
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use proto::prost::Message;
use http_private_key_manager::Request as RestRequest;

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut CreateProductRequest, hasher: D, signature: Vec<u8>) -> Result<CreateProductResponse, ApiError> {
    if request.version.len() < 1 {
        return Err(ApiError::InvalidRequest("The version must be at least one number".into()))
    }
    if request.timestamp < SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 60 {
        return Err(ApiError::InvalidRequest("Timestamp is too old".into()))
    }

    // the StoreId has already been verified in `decrypt_and_hash_request()` but
    // we still need to verify the signature against the public key in the db
    let client = DynamoDbClient::new(Region::UsEast1);
    let mut store_item = AttributeValueHashMap::new();
    let store_id = key_manager.get_store_id()?;
    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
    store_item.insert_item_into(STORES_TABLE.id, hashed_store_id.to_vec());

    let get_output = client.get_item(
        GetItemInput {
            table_name: STORES_TABLE.table_name.to_string(),
            key: store_item,
            consistent_read: Some(true),
            ..Default::default()
        }
    ).await?;
    
    store_item = match get_output.item {
        Some(x) => x,
        // It is very unlikely that this will happen, unless the salt used for 
        // hashing were to change... in which case, it would happen every time
        None => return Err(ApiError::NotFound)
    };

    let public_key = store_item.get_item(STORES_TABLE.public_key)?;
    // verify signature with public key
    let pubkey = PublicKey::from_sec1_bytes(&public_key)?;
    let verifier = VerifyingKey::from(pubkey);
    let signature = DerSignature::try_from(signature.as_slice())?;
    verifier.verify_digest(hasher, &signature)?;

    // signature verified
    // create plugin id and public key, and verify that it isn't already in the db
    let mut product_item = AttributeValueHashMap::new();
    
    let (product_id, product_pubkey) = loop {
        let (p_id, p_pk) = key_manager.generate_product_id(&request.product_id_prefix, &store_id)?;
        // hash plugin id before inserting it into table
        let hashed_product_id = salty_hash(&[p_id.binary_id.as_ref()], &PRODUCT_DB_SALT);
        product_item.insert_item_into(PRODUCTS_TABLE.id, hashed_product_id.to_vec());
        
        let get_output = &client.get_item(
            GetItemInput {
                table_name: PRODUCTS_TABLE.table_name.to_owned(),
                key: product_item.to_owned(),
                consistent_read: Some(true),
                ..Default::default()
            }
        ).await?;

        if get_output.item.is_none() {
            break (p_id, p_pk);
        }
    };

    // fill the product item with data
    let product_protobuf = ProductDbItem {
        version: request.version.to_owned(),
        store_id: store_id.binary_id.as_ref().into(),
        product_id: product_id.binary_id.as_ref().into(),
        product_name: request.product_name.to_owned(),
    };

    product_item.insert_item_into(
        PRODUCTS_TABLE.hashed_store_id, 
        salty_hash(&[store_id.binary_id.as_ref()], &PRODUCT_DB_SALT).to_vec()
    );

    product_item.insert_item(PRODUCTS_TABLE.is_offline_allowed, request.is_offline_allowed);
    product_item.insert_item(PRODUCTS_TABLE.max_machines_per_license, request.max_machines_per_license.to_string());

    product_item.insert_item_into(PRODUCTS_TABLE.num_machines_total, "0");
    product_item.insert_item_into(PRODUCTS_TABLE.num_licenses_total, "0");
    product_item.insert_item_into(PRODUCTS_TABLE.num_offline_machines, "0");
    product_item.insert_item_into(PRODUCTS_TABLE.num_subscription_machines, "0");
    product_item.insert_item_into(PRODUCTS_TABLE.num_perpetual_machines, "0");
    product_item.insert_item_into(PRODUCTS_TABLE.num_license_auths, "0");
    
    let encrypted_protobuf = key_manager.encrypt_db_proto(
        PRODUCTS_TABLE.table_name, 
        &product_id.binary_id.as_ref(), 
        &product_protobuf
    )?;
    product_item.insert_item_into(PRODUCTS_TABLE.protobuf_data, encrypted_protobuf);

    store_item.increase_number(&STORES_TABLE.num_products, 1)?;

    let mut request_items: HashMap<String, Vec<WriteRequest>> = HashMap::new();
    request_items.insert(STORES_TABLE.table_name.into(), vec![WriteRequest {
        put_request: Some(PutRequest { item: store_item } ),
        ..Default::default()
    }]);
    request_items.insert(PRODUCTS_TABLE.table_name.into(), vec![WriteRequest {
        put_request: Some(PutRequest { item: product_item } ),
        ..Default::default()
    }]);
    client.batch_write_item(BatchWriteItemInput {
        request_items,
        ..Default::default()
    }).await?;

    let response = CreateProductResponse {
        product_id: product_id.encoded_id,
        product_public_key: product_pubkey.to_vec(),
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
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
        CreateProductRequest,
        CreateProductResponse,
        sha2::Sha384,
        signature,
        chosen_symm_algo.as_str(),
        false,                     // is_handshake    
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
