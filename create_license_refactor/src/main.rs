//! A license creation API method for a licensing service.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use proto::protos::create_license_request::product_info::LicenseType::*;
use utils::aws_config::meta::region::RegionProviderChain;
use utils::aws_sdk_dynamodb::types::{AttributeValue, KeysAndAttributes, PutRequest, Select, WriteRequest};
use utils::aws_sdk_dynamodb::Client;
use utils::dynamodb::maps::Maps;
use proto::protos::{
    create_license_request::{CreateLicenseRequest, CreateLicenseResponse},
    store_db_item::StoreDbItem,
    license_db_item::LicenseDbItem,
};
use utils::get_license::construct_get_license_response_from_license_item;
use utils::init_license::init_license;
use utils::tables::metrics::METRICS_TABLE;
use utils::{debug_log, error_log, impl_function_handler, prelude::*};
use utils::tables::licenses::LICENSES_TABLE;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};

impl_function_handler!(
    CreateLicenseRequest,
    CreateLicenseResponse,
    ApiError,
    false
);

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut CreateLicenseRequest, hasher: D, signature: Vec<u8>) -> Result<CreateLicenseResponse, ApiError> {
    debug_log!("In process_request");
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
    debug_log!("Passed basic validation");

    let client = init_dynamodb_client!();
    debug_log!("Set up db client");

    let mut request_items: HashMap<String, KeysAndAttributes> = HashMap::new();

    let store_id = key_manager.get_store_id()?;
    debug_log!("Got the store id");

    let mut store_item = AttributeValueHashMap::new();
    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
    
    store_item.insert_item(&STORES_TABLE.id, Blob::new(hashed_store_id.to_vec()));
    
    request_items.insert(STORES_TABLE.table_name.to_string(),   KeysAndAttributes::builder()
            .set_keys(Some(vec![store_item.clone()]))
            .consistent_read(false)
            .build()?
    );

    request_items.insert(METRICS_TABLE.table_name.to_string(),
        KeysAndAttributes::builder()
            .set_keys(Some(vec![store_item]))
            .consistent_read(false)
            .build()?
    );
    debug_log!("Inserted store table into request_items");

    // insert product ids into request_items
    let product_map_keys: Vec<&String> = request.product_info.keys().collect();

    // check for pre-existing license
    let mut license_item = AttributeValueHashMap::new();
    
    let secondary_index = salty_hash(
        &[store_id.binary_id.as_ref(), request.user_id.as_bytes()],
        &LICENSE_DB_SALT
    );

    // user_id_hash-index is a global secondary index in dynamoDB, which only
    // copies the keys so that there won't be 2x the data for the Licenses 
    // table
    let query = client.query()
        .table_name(LICENSES_TABLE.table_name)
        .index_name(LICENSES_TABLE.hashed_store_id_and_user_id.index_name)
        .consistent_read(false)
        .key_condition_expression("#user_id_hash = :key_value")
        .expression_attribute_names("#user_id_hash", LICENSES_TABLE.hashed_store_id_and_user_id.item.key)
        .expression_attribute_values(":key_value", AttributeValue::B(Blob::new(secondary_index.to_vec())))
        .select(Select::AllProjectedAttributes)
        .send()
        .await;
    debug_log!("queried for existing licenses");

    let query = match query {
        Ok(v) => v,
        Err(e) => {
            let err = e.into_service_error();
            error_log!("Query Error: {}", err.to_string());
            return Err(err.into())
        }
    };

    let does_license_exist = if let Some(q) = query.items {
        if q.len() == 0 {
            false
        } else {
            license_item = q[0].clone();
            // remove the secondary index so we can get the full item
            license_item.remove(LICENSES_TABLE.hashed_store_id_and_user_id.item.key);
            true
        }
    } else {
        false
    };

    if does_license_exist {
        request_items.insert(LICENSES_TABLE.table_name.to_string(), KeysAndAttributes::builder()
            .set_keys(Some(vec![license_item.clone()]))
            .consistent_read(true)
            .build()?
    );
    }

    let batch_get = client.batch_get_item()
        .set_request_items(Some(request_items))
        .send()
        .await?;

    debug_log!("Received batch_get items");

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
    debug_log!("Set the store_item");

    let mut metrics_item = if let Some(s) = tables.get(METRICS_TABLE.table_name) {
        if s.len() != 1 {
            return Err(ApiError::NotFound)
        }
        s[0].clone()
    } else {
        return Err(ApiError::NotFound)
    };

    let store_item_protobuf: StoreDbItem = key_manager.decrypt_db_proto(
        &STORES_TABLE.table_name,
        store_id.binary_id.as_ref(),
        store_item.get_item(&STORES_TABLE.protobuf_data)?.as_ref()
    )?;
    debug_log!("Decrypted the StoreDbItem");

    let store_config = if let Some(c) = &store_item_protobuf.configs {
        c
    } else {
        return Err(ApiError::InvalidDbSchema("Missing store config".into()))
    };
    debug_log!("Set the store_config");

    verify_signature(&store_item, hasher, &signature)?;
    debug_log!("Verified the signature");

    let store_products_info = &store_item_protobuf.product_ids;
    // make sure all products are present in the database
    for k in product_map_keys.iter() {
        if !store_products_info.contains_key(k.as_str()) {
            return Err(ApiError::NotFound)
        }
    }
    debug_log!("All items are present in the PRODUCTS_TABLE");

    // check for pre-existing license
    let (_license_code, _offline_code) = if let Some(l) = tables.get(LICENSES_TABLE.table_name) {
        if l.len() == 0 {
            init_license(&client, key_manager, Some((&secondary_index, &request)), &mut license_item, &store_id).await?
        } else {
            // update license as necessary and return info
            license_item = l[0].clone();
            let primary_key = license_item.get_item(&LICENSES_TABLE.id)?;
            let protobuf: LicenseDbItem = key_manager.decrypt_db_proto(
                LICENSES_TABLE.table_name, 
                &primary_key.as_ref(), 
                license_item.get_item(&LICENSES_TABLE.protobuf_data)?.as_ref()
            )?;
            let license_code = bytes_to_license(&protobuf.license_id);

            (license_code, protobuf.offline_secret.clone())
        }
    } else {
        // init new license with request data
        init_license(&client, key_manager, Some((&secondary_index, &request)), &mut license_item, &store_id).await?
    };
    debug_log!("Initialized or set license_code");

    // update products in license map
    let (mut products_map, mut_products_map) = license_item.get_item_mut(&LICENSES_TABLE.products_map_item)?;
    debug_log!("Got mut products_map");

    // some updates might fail, such as if the user is trying to obtain a trial 
    // for the same product again
    let mut issues: HashMap<String, String> = HashMap::new();
    for product_id_string in product_map_keys.iter() {
        debug_log!("In product_map_keys loop");
        let product_info = store_products_info.get(product_id_string.as_str()).expect("We have checked that these exist");
        let machines_per_license = product_info.max_machines_per_license;
        let product_info = request.product_info.get(product_id_string.as_str()).expect("valid key");
        // leniency adds a little extra time to the initial expiration period to 
        // counteract any potential delays from server communications
        let subscription_leniency_seconds = store_config.subscription_license_expiration_leniency_hours as u64 * 60 * 60;

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let purchased_license_type = match &product_info.license_type {
            None => return Err(ApiError::InvalidRequest("Invalid ProductInfo structure".into())),
            Some(v) => v
        };

        let (mut license_info, mut_license_info) = if let Ok((mut existing_license_info, mut_existing_license_info)) = products_map.get_mut_map_by_str(&product_id_string) {
            // product map exists in the license map; user owns/owned a license for this product
            let existing_license_type = existing_license_info.get_item(&LICENSES_TABLE.products_map_item.fields.license_type)?.to_lowercase();
            match purchased_license_type {
                PerpetualLicense(v) => {
                    if existing_license_type.eq(license_types::PERPETUAL) {
                        // increase max machines by quantity * max_machines per license
                        existing_license_info.increase_number(&LICENSES_TABLE.products_map_item.fields.machines_allowed, machines_per_license as u64 * v.quantity as u64)?;
                        (existing_license_info, mut_existing_license_info)
                    } else {
                        // user is switching from either a trial license or a subscription; set max machines to base amount * quantity
                        existing_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.license_type, license_types::PERPETUAL.to_string());
                        existing_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.machines_allowed, (machines_per_license * v.quantity).to_string());
                        

                        (existing_license_info, mut_existing_license_info)
                    }
                },
                Subscription(v) => {
                    if existing_license_type.eq(license_types::SUBSCRIPTION) {
                        // user owns subscription
                        // extend expiry time
                        let (mut expiry_time, mut_expiry_time) = existing_license_info.get_item_mut(&LICENSES_TABLE.products_map_item.fields.expiry_time)?;
                        if expiry_time.ne("0") {
                            let expiry_time_seconds = expiry_time.parse::<u64>().expect("Should be valid");
                            // adjust expiry time based on whether the expiry time has already passed
                            if expiry_time_seconds < now {
                                expiry_time = (now + v.subscription_period + subscription_leniency_seconds).to_string();
                            } else {
                                expiry_time = (v.subscription_period + expiry_time_seconds).to_string();
                            }
                            *mut_expiry_time = AttributeValue::N(expiry_time)
                        }
                    } else if existing_license_type.eq(license_types::PERPETUAL) {
                        // attempting to switch from perpetual to subscription
                        issues.insert(product_id_string.to_string(), "You cannot purchase a subscription if you already own a perpetual license".into());
                    } else if existing_license_type.eq(license_types::TRIAL) {
                        // switching from trial to subscription
                        existing_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.license_type, license_types::SUBSCRIPTION.into());
                        existing_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.machines_allowed, machines_per_license.to_string());
                    }
                    (existing_license_info, mut_existing_license_info)
                },
                TrialLicense(_v) => {
                    issues.insert(product_id_string.to_string(), "You cannot purchase a trial if you have previously owned a license for this product.".into());
                    continue;
                }
            }        
        } else {
            // product map does not exist in the license map; user has not owned a license for this product
            products_map.insert_map(&product_id_string, AttributeValueHashMap::new());
            let(mut new_license_info, mut_new_license_info) = products_map.get_mut_map_by_str(&product_id_string).expect("We just set this");
            new_license_info.insert_item_into(&LICENSES_TABLE.products_map_item.fields.activation_time, "0");
            
            match purchased_license_type {
                TrialLicense(_v) => {
                    new_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.machines_allowed, machines_per_license.to_string());
                    new_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.license_type, license_types::TRIAL.into());
                },
                PerpetualLicense(v) => {
                    new_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.machines_allowed, (machines_per_license * v.quantity).to_string());
                    new_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.license_type, license_types::PERPETUAL.into());
                },
                Subscription(v) => {
                    new_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.license_type, license_types::SUBSCRIPTION.into());
                    new_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.machines_allowed, machines_per_license.to_string());
                    new_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.expiry_time, (now + v.subscription_period + subscription_leniency_seconds).to_string());
                },
            };

            new_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.online_machines, HashMap::new());
            new_license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.offline_machines, HashMap::new());

            (new_license_info, mut_new_license_info)
        };

        license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.is_subscription_active, true);
        license_info.insert_item(&LICENSES_TABLE.products_map_item.fields.is_license_active, true);
        *mut_license_info = AttributeValue::M(license_info);
    }
    debug_log!("Out of product_map_keys loop");

    *mut_products_map = AttributeValue::M(products_map);

    // update metrics table
    metrics_item.increase_number(&METRICS_TABLE.num_licenses, 1)?;
    debug_log!("Increased num_licenses");

    // write to database
    let mut write_request_map: HashMap<String, Vec<WriteRequest>> = HashMap::new();
    write_request_map.insert(METRICS_TABLE.table_name.into(), vec![WriteRequest::builder()
        .put_request(PutRequest::builder()
            .set_item(Some(metrics_item))
            .build()?
        ).build()
    ]);
    debug_log!("Inserted store_item into write_requests_map");

    write_request_map.insert(LICENSES_TABLE.table_name.into(), vec![WriteRequest::builder()
        .put_request(PutRequest::builder()
            .set_item(Some(license_item.clone()))
            .build()?
        ).build()
    ]);
    debug_log!("Inserted license_item into write_requests_map");

    client.batch_write_item()
        .set_request_items(Some(write_request_map))
        .send()
        .await?;
    debug_log!("Sent batch_write_item");

    let get_license_response = construct_get_license_response_from_license_item(key_manager, &license_item)?;

    let response = CreateLicenseResponse {
        license_info: get_license_response.encode_length_delimited_to_vec(),
        issues
    };

    Ok(response)
}