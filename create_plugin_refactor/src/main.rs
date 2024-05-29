//! A plugin creation API method for a licensing service.

use std::collections::HashMap;
use utils::aws_config::meta::region::RegionProviderChain;
use utils::aws_sdk_dynamodb::types::{PutRequest, WriteRequest};
use utils::aws_sdk_dynamodb::Client;
use utils::aws_sdk_s3::primitives::Blob;
use utils::crypto::p384::ecdsa::Signature;
use utils::crypto::sha2::Sha384;
use utils::dynamodb::maps::Maps;
use proto::protos::{
    product_db_item::ProductDbItem,
    create_product_request::{CreateProductRequest, CreateProductResponse},
};
use utils::prelude::proto::protos::store_db_item::StoreDbItem;
use utils::{debug_log, prelude::*};
use utils::tables::products::PRODUCTS_TABLE;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use proto::prost::Message;
use http_private_key_manager::{Request as RestRequest, Response as RestResponse};

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut CreateProductRequest, hasher: D, signature: Vec<u8>) -> Result<CreateProductResponse, ApiError> {
    if request.version.len() < 1 {
        return Err(ApiError::InvalidRequest("The version must be at least one number".into()))
    }

    // the StoreId has already been verified in `decrypt_and_hash_request()` but
    // we still need to verify the signature against the public key in the db
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let aws_config = utils::aws_config::from_env().region(region_provider).load().await;
    let client = Client::new(&aws_config);
    
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

    let public_key = store_item.get_item(STORES_TABLE.public_key)?;
    // verify signature with public key
    let pubkey = PublicKey::from_sec1_bytes(&public_key.as_ref())?;
    let verifier = VerifyingKey::from(pubkey);
    let signature: Signature = Signature::from_bytes(signature.as_slice().try_into().unwrap())?;
    verifier.verify_digest(hasher, &signature)?;

    // signature verified
    // create plugin id and public key, and verify that it isn't already in the db
    let mut product_item = AttributeValueHashMap::new();
    
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
    
    let encrypted_protobuf = key_manager.encrypt_db_proto(
        PRODUCTS_TABLE.table_name, 
        &product_id.binary_id.as_ref(), 
        &product_protobuf
    )?;
    product_item.insert_item(PRODUCTS_TABLE.protobuf_data, Blob::new(encrypted_protobuf));

    store_item.increase_number(&STORES_TABLE.num_products, 1)?;

    let mut store_proto: StoreDbItem = key_manager.decrypt_db_proto(
        &STORES_TABLE.table_name,
        store_id.binary_id.as_ref(),
        store_item.get_item(STORES_TABLE.protobuf_data)?.as_ref()
    )?;
    store_proto.product_ids.push(product_id.binary_id.as_ref().to_vec());
    store_item.insert_item(
        STORES_TABLE.protobuf_data,
        Blob::new(key_manager.encrypt_db_proto(
            &STORES_TABLE.table_name, 
            store_id.binary_id.as_ref(), 
            &store_proto
        )?)
    );

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

    client.batch_write_item()
        .set_request_items(Some(request_items))
        .send()
        .await?;
    
    let response = CreateProductResponse {
        product_id: product_id.encoded_id,
        product_public_key: product_pubkey.to_vec(),
    };

    Ok(response)
}

async fn handle_crypto(key_manager: &mut KeyManager, request: &mut RestRequest, req_bytes: &[u8], is_handshake: bool, chosen_symmetric_algorithm: &str, signature: Vec<u8>) -> Result<(RestResponse, Signature), ApiError> {
    type Req = CreateProductRequest;
    type Resp = CreateProductResponse;
    match chosen_symmetric_algorithm {
        "chacha20poly1305" => {
            let (mut decrypted, hash) = {
                debug_log!("In chacha20poly1305 segment");
                let result = key_manager.decrypt_and_hash_request::<ChaCha20Poly1305, Sha384, Req>(request, req_bytes, is_handshake);
                debug_log!("Got result in chacha20poly1305 segment");
                result.unwrap()
            };
            debug_log!("Sending result to process_request()");
            let mut response = process_request(key_manager, &mut decrypted, hash, signature).await?;
            debug_log!("Encrypting and signing the response");
            Ok(key_manager.encrypt_and_sign_response::<ChaCha20Poly1305, Resp>(&mut response)?)
        },
        "aes-gcm-128" => {
            debug_log!("In aes-gcm-128 segment");
            let (mut decrypted, hash) = key_manager.decrypt_and_hash_request::<Aes128Gcm, Sha384, Req>(request, req_bytes, is_handshake)?;
            let mut response = process_request(key_manager, &mut decrypted, hash, signature).await?;
            Ok(key_manager.encrypt_and_sign_response::<Aes128Gcm, Resp>(&mut response)?)
        },
        "aes-gcm-256" => {
            debug_log!("In aes-gcm-256 segment");
            let (mut decrypted, hash) = key_manager.decrypt_and_hash_request::<Aes256Gcm, Sha384, Req>(request, req_bytes, is_handshake)?;
            let mut response = process_request(key_manager, &mut decrypted, hash, signature).await?;
            Ok(key_manager.encrypt_and_sign_response::<Aes256Gcm, Resp>(&mut response)?)
        }
        _ => {
            debug_log!("Invalid symmetric encryption algorithm error");
            return Err(ApiError::InvalidRequest("Invalid symmetric encryption algorithm".into()))
        }
    }
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

    let chosen_symmetric_algorithm = request.symmetric_algorithm.to_lowercase();
    let crypto_result = handle_crypto(&mut key_manager, &mut request, req_bytes, false, &chosen_symmetric_algorithm, signature).await;
    
    let (encrypted, signature) = if let Ok(v) = crypto_result {
        v
    } else {
        return crypto_result.unwrap_err().respond()
    };

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
