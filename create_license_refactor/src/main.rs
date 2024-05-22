//! A license creation API method for a licensing service.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use utils::crypto::http_private_key_manager::private_key_generator::elliptic_curve::rand_core::RngCore;
use utils::crypto::http_private_key_manager::Id;
use utils::dynamodb::maps::Maps;
use utils::prelude::proto::protos::create_license_request::{CreateLicenseRequest, LicenseDbItem};
use utils::prelude::proto::protos::create_license_response::CreateLicenseResponse;
use utils::prelude::proto::protos::create_product_request::ProductDbItem;
use utils::prelude::rusoto_dynamodb::{BatchGetItemInput, BatchWriteItemInput, KeysAndAttributes, PutRequest, WriteRequest};
use utils::prelude::*;
use utils::tables::licenses::LICENSES_TABLE;
use utils::tables::products::PRODUCTS_TABLE;
use utils::tables::stores::STORES_TABLE;
use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDbClient, DynamoDb};
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use proto::prost::Message;
use http_private_key_manager::Request as RestRequest;

fn init_license(key_manager: &mut KeyManager, request: &CreateLicenseRequest, license_item: &mut AttributeValueHashMap, store_id: &Id<StoreId>) -> Result<(String, String), ApiError> {
    let license_code = key_manager.generate_license_code(&store_id)?;
    let primary_index = salty_hash(&[store_id.binary_id.as_ref(), license_code.binary_id.as_ref()], LICENSE_DB_SALT);
    license_item.insert_item_into(LICENSES_TABLE.id, primary_index.to_vec());
    license_item.insert_item_into(LICENSES_TABLE.custom_success_message, request.custom_success_message.clone());
    license_item.insert_item_into(LICENSES_TABLE.email_hash, salty_hash(&[request.customer_email.as_bytes()], LICENSE_DB_SALT).to_vec());
    license_item.insert_item(LICENSES_TABLE.products_map_item.key, AttributeValueHashMap::new());
    
    let offline_secret_u16 = key_manager.rng.next_u32() as u16;
    let offline_secret = format!("{:x}", offline_secret_u16);
    let protobuf_data = LicenseDbItem {
        license_id: license_code.binary_id.as_ref().to_vec(),
        customer_first_name: request.customer_first_name.clone(),
        customer_last_name: request.customer_last_name.clone(),
        customer_email: request.customer_email.clone(),
        offline_secret: offline_secret.clone(),
    };
    let encrypted = key_manager.encrypt_db_proto(LICENSES_TABLE.table_name, &license_code.binary_id.as_ref(), &protobuf_data)?;
    license_item.insert_item_into(LICENSES_TABLE.protobuf_data, encrypted);
    Ok((license_code.encoded_id, offline_secret))
}

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut CreateLicenseRequest, hasher: D, signature: Vec<u8>) -> Result<CreateLicenseResponse, ApiError> {
    if request.custom_success_message.len() > 140 {
        return Err(ApiError::InvalidRequest("The custom success message must be less than 140 chars".into()))
    }
    if request.customer_email.len() > 254 {
        return Err(ApiError::InvalidRequest("Customer email is too long".into()))
    }
    if request.order_id.len() > 48 {
        return Err(ApiError::InvalidRequest("Order ID is too long".into()))
    }
    if request.user_id.len() > 48 {
        return Err(ApiError::InvalidRequest("User ID is too long".into()))
    }
    if request.timestamp < SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - 60 {
        return Err(ApiError::InvalidRequest("Timestamp is too old".into()))
    }

    let mut request_items: HashMap<String, KeysAndAttributes> = HashMap::new();

    let store_id = key_manager.get_store_id()?;

    let mut store_item = AttributeValueHashMap::new();
    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], STORE_DB_SALT);
    
    store_item.insert_item(STORES_TABLE.id, hashed_store_id.to_vec().into());
    
    request_items.insert(STORES_TABLE.table_name.to_string(), KeysAndAttributes {
        consistent_read: Some(true),
        keys: vec![store_item],
        ..Default::default()
    });

    // insert product ids into request_items
    let product_map_keys: Vec<&String> = request.product_info.keys().collect();
    let mut product_items: HashMap<String, AttributeValueHashMap> = HashMap::new();
    // for finding the product-tablehash of a product id
    let mut pid_hash_to_product_id_hmap: HashMap<Bytes, String> = HashMap::new();
    for k in product_map_keys.iter() {
        let mut product_item = AttributeValueHashMap::new();
        let (product_id, _) = key_manager.validate_product_id(&k, &store_id)?;
        let hashed_product_id = salty_hash(&[product_id.binary_id.as_ref()], PRODUCT_DB_SALT);
        product_item.insert_item_into(PRODUCTS_TABLE.id, hashed_product_id.to_vec());
        product_items.insert(k.to_string(), product_item);
        pid_hash_to_product_id_hmap.insert(hashed_product_id.to_vec().into(), k.to_string());
    }
    request_items.insert(PRODUCTS_TABLE.table_name.to_string(), KeysAndAttributes {
        keys: product_items.values().cloned().collect(),
        consistent_read: Some(true),
        ..Default::default()
    });

    // check for pre-existing license
    let mut license_item = AttributeValueHashMap::new();
    
    let secondary_index = salty_hash(
        &[store_id.binary_id.as_ref(), request.user_id.as_bytes()],
        LICENSE_DB_SALT
    );
    license_item.insert_item_into(LICENSES_TABLE.hashed_store_id_and_user_id, secondary_index.to_vec());
    request_items.insert(LICENSES_TABLE.table_name.to_string(), KeysAndAttributes {
        keys: vec![license_item.clone()],
        consistent_read: Some(true),
        ..Default::default()
    });

    let client = DynamoDbClient::new(Region::UsEast1);

    let batch_get = client.batch_get_item(BatchGetItemInput {
        request_items,
        ..Default::default()
    }).await?;

    let tables = if let Some(r) = batch_get.responses {
        r
    } else{
        return Err(ApiError::NotFound);
    };

    store_item = if let Some(s) = tables.get(STORES_TABLE.table_name) {
        if s.len() != 1 {
            return Err(ApiError::NotFound)
        }
        s[0].clone()
    } else {
        return Err(ApiError::NotFound)
    };

    // verify signature
    let public_key = store_item.get_item(STORES_TABLE.public_key)?;
    let pubkey = PublicKey::from_sec1_bytes(&public_key)?;
    let verifier = VerifyingKey::from(pubkey);
    let signature = DerSignature::try_from(signature.as_slice())?;
    verifier.verify_digest(hasher, &signature)?;

    // make sure all products are present in the database
    if let Some(ref p) = tables.get(PRODUCTS_TABLE.table_name) {
        if p.len() != product_map_keys.len() {
            return Err(ApiError::NotFound)
        }
        // ensure that product items are pointing to the responses from the db
        for prod in p.iter() {
            let id = prod.get_item(PRODUCTS_TABLE.id)?;
            
            let map = product_items.get_mut(
                pid_hash_to_product_id_hmap.get(id).expect("hmap should contain the value")
            ).expect("hmap should contain the value");
            *map = prod.clone();
        }
    } else {
        return Err(ApiError::NotFound)
    };

    // check for pre-existing license
    let (license_code, offline_code) = if let Some(l) = tables.get(LICENSES_TABLE.table_name) {
        if l.len() == 0 {
            init_license(key_manager, request, &mut license_item, &store_id)?
        } else {
            // update license as necessary and return info
            license_item = l[0].clone();
            let protobuf: LicenseDbItem = key_manager.decrypt_db_proto(
                LICENSES_TABLE.table_name, 
                &store_id.binary_id.as_ref(), 
                license_item.get_item(LICENSES_TABLE.protobuf_data)?
            )?;
            let license_code = bytes_to_license(&protobuf.license_id);

            (license_code, protobuf.offline_secret.clone())
        }
    } else {
        // init new license with request data
        init_license(key_manager, request, &mut license_item, &store_id)?
    };

    let mut machine_limits: HashMap<String, u64> = HashMap::new();
    // update products in license map
    let products_map = license_item.get_item_mut(LICENSES_TABLE.products_map_item.key)?;
    // some updates might fail, such as if the user is trying to obtain a trial 
    // for the same product again
    let mut issues: HashMap<String, String> = HashMap::new();
    for product_id_string in product_map_keys.iter() {
        let product_item = product_items.get(product_id_string.as_str()).expect("key should exist");
        let protobuf_bytes = product_item.get_item(PRODUCTS_TABLE.protobuf_data)?;
        let product_protobuf_data: ProductDbItem = key_manager.decrypt_db_proto(PRODUCTS_TABLE.table_name, &store_id.binary_id.as_ref(), &protobuf_bytes)?;
        let machines_per_license = product_item.get_item(PRODUCTS_TABLE.max_machines_per_license)?.parse::<u64>()?;
        let product_info = request.product_info.get(product_id_string.as_str()).expect("valid key");
        let subscription_expiration_period = product_protobuf_data.subscription_license_expiration_days;
        let subscription_expiration_period_seconds = (subscription_expiration_period as u64) * 60 * 60 * 24;
        // leniency adds a little extra time to the initial expiration period to 
        // counteract any potential delays from server communications
        let subscription_leniency_seconds = product_protobuf_data.subscription_license_expiration_leniency_hours as u64 * 60 * 60;
        // validate license types in request
        let types = &[license_types::PERPETUAL, license_types::SUBSCRIPTION, license_types::TRIAL];
        if !types.contains(&product_info.license_type.to_lowercase().as_str()) {
            return Err(ApiError::InvalidRequest("License type in request is invalid".into()))
        }
        let purchased_license_type = product_info.license_type.to_lowercase();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let license_info = if let Ok(existing_license_info) = products_map.get_mut_map_by_str(&product_id_string) {
            // product map exists in the license map; user owns/owned a license
            // for this product
            // check that newly purchased license is not a trial license
            if purchased_license_type == license_types::TRIAL {
                issues.insert(product_id_string.to_string(), "You cannot purchase a trial if you have previously owned a license for this product.".into());
                continue;
            }
            // update license info in product map
            let existing_license_type = existing_license_info.get_item(LICENSES_TABLE.products_map_item.fields.license_type)?;
            if &purchased_license_type == existing_license_type && purchased_license_type != license_types::SUBSCRIPTION {
                // increase machines by quantity * max_machines_per_license
                let num_machines = existing_license_info.increase_number(&LICENSES_TABLE.products_map_item.fields.machines_allowed, machines_per_license * product_info.quantity as u64)?;
                machine_limits.insert(product_id_string.to_string(), num_machines);
            } else if &purchased_license_type == existing_license_type && purchased_license_type == license_types::SUBSCRIPTION {
                // extend expiry time
                let expiry_time = existing_license_info.get_item_mut(LICENSES_TABLE.products_map_item.fields.expiry_time)?;
                if expiry_time != "0" {
                    let expiry_time_seconds = expiry_time.parse::<u64>().expect("Should be valid");
                    // adjust expiry time based on whether the expiry time has already passed
                    if expiry_time_seconds < now {
                        *expiry_time = (now + subscription_expiration_period_seconds + subscription_leniency_seconds).to_string();
                    } else {
                        *expiry_time = (subscription_expiration_period_seconds + expiry_time_seconds).to_string();
                    }
                }
            } else {
                // license type purchased is different than the existing one
                if purchased_license_type == license_types::SUBSCRIPTION && existing_license_type == license_types::PERPETUAL {
                    // user should probably not purchase a subscription license
                    // if they already own a perpetual license
                    issues.insert(product_id_string.to_string(), "You cannot purchase a subscription license if you already own a perpetual license.".into());
                    continue;
                } else if purchased_license_type == license_types::SUBSCRIPTION {
                    // user upgraded from trial license to subscription license
                    existing_license_info.insert_item(LICENSES_TABLE.products_map_item.fields.expiry_time, (now + subscription_expiration_period_seconds).to_string())
                }
                
                // since the only license types are `Perpetual`, `Subscription`, 
                // and `Trial`, this must be either Trial -> Perpetual or 
                // Subscription -> Perpetual.
                let max_machines = existing_license_info.get_item_mut(LICENSES_TABLE.products_map_item.fields.machines_allowed)?;
                let new_limit = product_info.quantity as u64 * machines_per_license;
                *max_machines = new_limit.to_string();
                machine_limits.insert(product_id_string.to_string(), new_limit);
                existing_license_info.insert_item_into(LICENSES_TABLE.products_map_item.fields.license_type, purchased_license_type);
                
            }
            existing_license_info
        } else {
            // product map does not exist in the license map; user does not
            // already own a license for this product
            products_map.insert_map(&product_id_string, Some(AttributeValueHashMap::new()));
            let new_license_info = products_map.get_mut_map_by_str(&product_id_string).expect("We just set this");
            new_license_info.insert_item_into(LICENSES_TABLE.products_map_item.fields.activation_time, "0");
            
            if purchased_license_type == license_types::TRIAL {
                new_license_info.insert_item(LICENSES_TABLE.products_map_item.fields.machines_allowed, machines_per_license.to_string());
                machine_limits.insert(product_id_string.to_string(), machines_per_license);
            } else {
                let total_machines = machines_per_license * product_info.quantity as u64;
                new_license_info.insert_item(LICENSES_TABLE.products_map_item.fields.machines_allowed, total_machines.to_string());
                machine_limits.insert(product_id_string.to_string(), total_machines);
                
                // initialize expiry_time for subscription licenses
                if purchased_license_type == license_types::SUBSCRIPTION {
                    new_license_info.insert_item(LICENSES_TABLE.products_map_item.fields.expiry_time, (now + subscription_expiration_period_seconds + subscription_leniency_seconds).to_string())
                }
            }
            new_license_info.insert_item_into(LICENSES_TABLE.products_map_item.fields.license_type, purchased_license_type);
            new_license_info.insert_item(LICENSES_TABLE.products_map_item.fields.online_machines.key, HashMap::new());
            new_license_info.insert_item(LICENSES_TABLE.products_map_item.fields.offline_machines.key, HashMap::new());
            
            new_license_info
        };
        license_info.insert_item(LICENSES_TABLE.products_map_item.fields.is_subscription_active, true);
        license_info.insert_item(LICENSES_TABLE.products_map_item.fields.is_license_active, true);
    }

    // update store table
    store_item.increase_number(&STORES_TABLE.num_licenses, 1)?;

    // write to database
    let mut write_request_map: HashMap<String, Vec<WriteRequest>> = HashMap::new();
    write_request_map.insert(STORES_TABLE.table_name.into(), vec![WriteRequest {
        put_request: Some(PutRequest { item: store_item } ), 
        ..Default::default()
    }]);
    write_request_map.insert(LICENSES_TABLE.table_name.into(), vec![WriteRequest {
        put_request: Some(PutRequest { item: license_item } ),
        ..Default::default()
    }]);

    client.batch_write_item(
        BatchWriteItemInput {
            request_items: write_request_map,
            ..Default::default()
        }
    ).await?;

    // respond to request
    let response = CreateLicenseResponse {
        license_code,
        offline_code,
        machine_limits,
        issues,
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
        CreateLicenseRequest,
        CreateLicenseResponse,
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
