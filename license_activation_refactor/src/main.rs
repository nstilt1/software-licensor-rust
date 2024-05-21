//! A license activation API method for a licensing service.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use utils::crypto::http_private_key_manager::Id;
use utils::dynamodb::maps::Maps;
use utils::prelude::proto::protos::create_license_request::LicenseDbItem;
use utils::prelude::proto::protos::create_product_request::ProductDbItem;
use utils::prelude::proto::protos::license_activation_request::LicenseActivationRequest;
use utils::prelude::proto::protos::license_activation_response::{LicenseActivationResponse, LicenseKeyFile};
use utils::prelude::rusoto_dynamodb::{BatchGetItemInput, BatchWriteItemInput, KeysAndAttributes, PutRequest, WriteRequest};
use utils::{now_as_seconds, prelude::*, StringSanitization};
use utils::tables::licenses::LICENSES_TABLE;
use utils::tables::products::PRODUCTS_TABLE;
use utils::tables::stores::STORES_TABLE;
use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDbClient, DynamoDb};
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use proto::prost::Message;
use http_private_key_manager::Request as RestRequest;

/// Checks the validity of the user-provided Offline License code, and returns 
/// the Customer's first and last name if it is filled out. This allows the name
/// to be displayed in the application.
fn check_licenses_db_proto(key_manager: &mut KeyManager, is_offline_attempt: bool, offline_license_code: &str, store_id: &Id<StoreId>, license_item: &AttributeValueHashMap) -> Result<(String, String), ApiError> {
    let decrypted_proto: LicenseDbItem = key_manager.decrypt_db_proto(
        &LICENSES_TABLE.table_name, 
        store_id, 
        license_item.get_item(LICENSES_TABLE.protobuf_data)?
    )?;
    if is_offline_attempt {
        if decrypted_proto.offline_secret.ne(offline_license_code) {
            return Err(ApiError::InvalidAuthentication)
        }
    }
    Ok((decrypted_proto.customer_first_name.clone(), decrypted_proto.customer_last_name.clone()))
}

fn update_lists(updated: &mut bool, license_product_item: &mut AttributeValueHashMap, online_list: Option<Vec<String>>, offline_list: Option<Vec<String>>) {
    //let mut product_map = license_product_map.to_owned();
    if let Some(online_machines) = online_list {
        license_product_item.insert_item(LICENSES_TABLE.products_map_item.fields.online_machines, online_machines);
        *updated = true;
    }
    if let Some(offline_machines) = offline_list {
        license_product_item.insert_item(LICENSES_TABLE.products_map_item.fields.offline_machines, offline_machines);
        *updated = true;
    }
}

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut LicenseActivationRequest, _hasher: D, _signature: ()) -> Result<LicenseActivationResponse, ApiError> {
    // there is no signature on this request
    let store_id = if let Ok(s) = key_manager.get_store_id() {
        s
    } else {
        return Err(ApiError::InvalidAuthentication)
    };
    let (product_id, _) = if let Ok(p) = key_manager.validate_product_id(&request.product_id, &store_id) {
        p
    } else {
        return Err(ApiError::InvalidAuthentication)
    };

    // check for offline license attempt
    let is_offline_attempt = request.license_code.to_lowercase().contains("offline");
    let (license_id, offline_license_code) = if is_offline_attempt {
        let len = request.license_code.len();
        let mut sanitized = request.license_code.as_str().sanitize_str("abcdefABCDEF1234567890");
        sanitized.truncate(LICENSE_CODE_LEN);
        (key_manager.validate_license_code(&sanitized, &store_id)?, &request.license_code[len-5..])
    } else {
        (key_manager.validate_license_code(&request.license_code, &store_id)?, "")
    };

    // store_id, product_id, and license_id have been validated
    // now we need to check and validate with the database
    let mut request_items: HashMap<String, KeysAndAttributes> = HashMap::new();


    let mut store_item = AttributeValueHashMap::new();
    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], STORE_DB_SALT);
    store_item.insert_item_into(STORES_TABLE.id, hashed_store_id.to_vec());
    request_items.insert(STORES_TABLE.table_name.to_string(), KeysAndAttributes {
        consistent_read: Some(true),
        keys: vec![store_item],
        ..Default::default()
    });

    let mut license_item = AttributeValueHashMap::new();
    let hashed_license_id = salty_hash(&[store_id.binary_id.as_ref(), license_id.binary_id.as_ref()], LICENSE_DB_SALT);
    license_item.insert_item_into(LICENSES_TABLE.id, hashed_license_id.to_vec());
    request_items.insert(LICENSES_TABLE.table_name.to_string(), KeysAndAttributes {
        consistent_read: Some(true),
        keys: vec![license_item],
        ..Default::default()
    });

    let mut product_item = AttributeValueHashMap::new();
    let hashed_product_id = salty_hash(&[product_id.binary_id.as_ref()], PRODUCT_DB_SALT);
    product_item.insert_item_into(PRODUCTS_TABLE.id, hashed_product_id.to_vec());
    request_items.insert(PRODUCTS_TABLE.table_name.to_string(), KeysAndAttributes {
        consistent_read: Some(false),
        keys: vec![product_item],
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
        return Err(ApiError::NotFound.into());
    };

    store_item = if let Some(s) = tables.get(STORES_TABLE.table_name) {
        if s.len() != 1 {
            return Err(ApiError::NotFound.into())
        }
        s[0].clone()
    } else {
        return Err(ApiError::NotFound.into())
    };

    product_item = if let Some(p) = tables.get(PRODUCTS_TABLE.table_name) {
        if p.len() != 1 {
            return Err(ApiError::NotFound)
        }
        p[0].clone()
    } else {
        return Err(ApiError::NotFound)
    };

    license_item = if let Some(l) = tables.get(LICENSES_TABLE.table_name) {
        if l.len() != 1 {
            return Err(ApiError::InvalidAuthentication)
        }
        l[0].clone()
    } else {
        return Err(ApiError::InvalidAuthentication)
    };

    // all items are present in the database
    // validate the license
    let hashed_product_id = salty_hash(&[product_id.binary_id.as_ref()], LICENSE_DB_SALT).to_base64();
    let mut products_map = license_item.get_item_mut(LICENSES_TABLE.products_map_item.key)?.to_owned();

    let license_product_map = products_map.get_mut_map_by_str(&hashed_product_id)?;
    let max_machines = license_product_map.get_item(LICENSES_TABLE.products_map_item.fields.machines_allowed)?.parse::<usize>()?;
    let mut offline_machines_list = license_product_map.get_item(LICENSES_TABLE.products_map_item.fields.offline_machines)?.to_owned();
    let mut online_machines_list = license_product_map.get_item(LICENSES_TABLE.products_map_item.fields.online_machines)?.to_owned();
    let current_machine_count = offline_machines_list.len() + online_machines_list.len();
    
    let exists_in_machine_list = offline_machines_list.contains(&request.machine_id) || online_machines_list.contains(&request.machine_id);

    let product_protobuf_data: ProductDbItem = key_manager.decrypt_db_proto(
        &PRODUCTS_TABLE.table_name, 
        &store_id, 
        product_item.get_item(PRODUCTS_TABLE.protobuf_data)?
    )?;
    let responses = match product_protobuf_data.language_support.get(&request.language_id) {
        Some(l) => l.to_owned(),
        None => return Err(ApiError::InvalidRequest("Language ID did not match the database".into()))
    };

    let expiry_time = license_item.get_item(LICENSES_TABLE.products_map_item.fields.expiry_time)?.parse::<u64>()?;
    let license_type = license_product_map.get_item(LICENSES_TABLE.products_map_item.fields.license_type)?.to_lowercase();

    let success_message = {
        let custom_message = license_item.get_item(LICENSES_TABLE.custom_success_message)?;
        if custom_message.len() > 0 {
            custom_message.clone()
        } else {
            responses.success.clone()
        }
    };

    let mut key_file = LicenseKeyFile {
        product_id: product_id.encoded_id.clone(),
        customer_first_name: "".into(),
        customer_last_name: "".into(),
        license_code: request.license_code.clone(),
        license_type: license_type.clone(),
        machine_id: request.machine_id.clone(),
        timestamp: now_as_seconds(),
        expiration_timestamp: None,
        check_back_timestamp: None,
        message: "".into(),
        post_expiration_message: "".into(),
    };
    
    // doing an OR operation instead of `.ne(license_types::PERPETUAL)` in case other license types get added
    let is_expiring = license_type.eq(license_types::TRIAL) || license_type.eq(license_types::SUBSCRIPTION);

    if is_expiring && expiry_time != 0 && expiry_time < SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() {
        // expiry time has been reached
        match license_type.as_str() {
            license_types::TRIAL => return Err(ApiError::TrialEnded(responses)),
            license_types::SUBSCRIPTION => return Err(ApiError::LicenseNoLongerActive(responses)),
            _ => unreachable!()
        }
    }
    let mut updated_license = false;

    // check offline code
    let (first_name, last_name) = check_licenses_db_proto(key_manager, is_offline_attempt, &offline_license_code, &store_id, &license_item)?;
    // check machine lists
    if !exists_in_machine_list {
        if current_machine_count < max_machines {
            product_item.increase_number(&PRODUCTS_TABLE.num_machines_total, 1)?;
            // success response, update tables
            if is_offline_attempt {
                offline_machines_list.push(request.machine_id.clone());
                product_item.increase_number(&PRODUCTS_TABLE.num_offline_machines, 1)?;
                update_lists(&mut updated_license, license_product_map, None, Some(offline_machines_list));
            } else {
                online_machines_list.push(request.machine_id.clone());
                update_lists(&mut updated_license, license_product_map, Some(online_machines_list), None);
            }
        } else {
            // machine limit reached
            return Err(ApiError::OverMaxMachines(responses))
        }
    } else {
        if is_offline_attempt {
            // remove machine from online machines list if it is there, then add it to offline machines list
            if let Some(pos) = online_machines_list.iter().position(|m| m == &request.machine_id) {
                online_machines_list.remove(pos);
                offline_machines_list.push(request.machine_id.clone());
                update_lists(&mut updated_license, license_product_map, Some(online_machines_list), Some(offline_machines_list));
            } else if !offline_machines_list.contains(&request.machine_id) {
                offline_machines_list.push(request.machine_id.clone());
                update_lists(&mut updated_license, license_product_map, None, Some(offline_machines_list));
            }
        }
    }
    
    let now = now_as_seconds();
    let (local_expire_time, check_up_time) = match license_type.as_str() {
        license_types::TRIAL => {
            let expire_time = if expiry_time == 0 {
                // trial license is being activated; set the expiry time accordingly
                let expire_time = now + (product_protobuf_data.trial_license_expiration_days as u64 * 24 * 60 * 60);
                license_product_map.insert_item(
                    LICENSES_TABLE.products_map_item.fields.expiry_time,
                    expire_time.to_string());
                updated_license = true;
                expire_time
            } else {
                license_product_map.get_item(LICENSES_TABLE.products_map_item.fields.expiry_time)?.parse::<u64>()?
            };
            let check_up_time = now + (product_protobuf_data.trial_license_frequency_hours as u64 * 60 * 60);
            key_file.post_expiration_message = responses.trial_ended;
            (expire_time, check_up_time)
        },
        license_types::SUBSCRIPTION => {
            let expire_time = now + (product_protobuf_data.subscription_license_expiration_days as u64 * 24 * 60 * 60);
            let check_up_time = now + (product_protobuf_data.subscription_license_frequency_hours as u64 * 60 * 60);
            key_file.post_expiration_message = responses.license_no_longer_active;
            (expire_time, check_up_time)
        },
        license_types::PERPETUAL => {
            let expire_time = now + (product_protobuf_data.perpetual_license_expiration_days as u64 * 24 * 60 * 60);
            let check_up_time = now + (product_protobuf_data.perpetual_license_frequency_hours as u64 * 60 * 60);
            (expire_time, check_up_time)
        },
        _ => return Err(ApiError::InvalidDbSchema("Invalid license type".into()))
    };

    // set expire time and check-up time
    if is_offline_attempt {
        key_file.expiration_timestamp = None
    } else {
        key_file.expiration_timestamp = Some(local_expire_time)
    }
     
    key_file.check_back_timestamp = Some(check_up_time);
    key_file.customer_first_name = first_name;
    key_file.customer_last_name = last_name;
    key_file.message = success_message;

    let mut write_requests: HashMap<String, Vec<WriteRequest>> = HashMap::new();

    if updated_license {
        write_requests.insert(
            LICENSES_TABLE.table_name.to_string(),
            vec![WriteRequest {
                put_request: Some(PutRequest { item: license_item } ),
                ..Default::default()
            }]
        );
    }

    store_item.increase_number(&STORES_TABLE.num_auths, 1)?;
    write_requests.insert(
        STORES_TABLE.table_name.to_string(),
        vec![WriteRequest {
            put_request: Some(PutRequest { item: store_item } ),
            ..Default::default()
        }]
    );

    product_item.increase_number(&PRODUCTS_TABLE.num_license_auths, 1)?;
    write_requests.insert(
        PRODUCTS_TABLE.table_name.to_string(),
        vec![WriteRequest {
            put_request: Some(PutRequest { item: product_item } ),
            ..Default::default()
        }]
    );

    client.batch_write_item(BatchWriteItemInput {
        request_items: write_requests,
        ..Default::default()
    }).await?;

    let signature = key_manager.sign_key_file(&key_file.encode_to_vec(), &product_id)?;
    let response = LicenseActivationResponse {
        key_file: Some(key_file),
        key_file_signature: signature,
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
        LicenseActivationRequest,
        LicenseActivationResponse,
        sha2::Sha384,
        (),
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
