//! A license activation API method for a licensing service.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use http_private_key_manager::prelude::years_to_seconds;
use utils::aws_sdk_dynamodb::types::{AttributeValue, KeysAndAttributes, PutRequest, WriteRequest};
use utils::dynamodb::maps::Maps;
use proto::protos::{
    license_db_item::LicenseDbItem,
    license_activation_request::{
        LicenseActivationRequest,
        LicenseActivationResponse,
        LicenseKeyFile,
        Stats,
    },
};
use utils::prelude::proto::protos::store_db_item::StoreDbItem;
use utils::tables::machines::MACHINES_TABLE;
use utils::tables::metrics::METRICS_TABLE;
use utils::{now_as_seconds, prelude::*};
use utils::tables::licenses::{LICENSES_TABLE, MACHINE};
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use utils::aws_sdk_dynamodb::Client;
use utils::aws_config::meta::region::RegionProviderChain;

/// Checks the validity of the user-provided Offline License code, and returns 
/// the Customer's first and last name if it is filled out. This allows the name
/// to be displayed in the application.
/// 
/// Returns customer's (first name, last name, email)
fn check_licenses_db_proto(key_manager: &mut KeyManager, is_offline_attempt: bool, offline_license_code: &str, license_item: &AttributeValueHashMap) -> Result<(String, String, String), ApiError> {
    debug_log!("In check_licenses_db_proto");
    let decrypted_proto: LicenseDbItem = key_manager.decrypt_db_proto(
        &LICENSES_TABLE.table_name, 
        license_item.get_item(&LICENSES_TABLE.id)?.as_ref(), 
        license_item.get_item(&LICENSES_TABLE.protobuf_data)?.as_ref()
    )?;
    debug_log!("Decrypted LicenseDbItem");
    if is_offline_attempt {
        if decrypted_proto.offline_secret.to_lowercase().ne(&offline_license_code.to_lowercase()) {
            return Err(ApiError::IncorrectOfflineCode)
        }
    }
    debug_log!("Passed the is_offline_attempt check");
    Ok(
        (
            decrypted_proto.customer_first_name.clone(), 
            decrypted_proto.customer_last_name.clone(),
            decrypted_proto.customer_email.clone()
        )
    )
}

fn update_lists(updated: &mut bool, license_product_item: &mut AttributeValueHashMap, online_list: Option<AttributeValueHashMap>, offline_list: Option<AttributeValueHashMap>) {
    debug_log!("In update_lists");
    //let mut product_map = license_product_map.to_owned();
    if let Some(online_machines) = online_list {
        license_product_item.insert_item(&LICENSES_TABLE.products_map_item.fields.online_machines, online_machines);
        *updated = true;
    }
    if let Some(offline_machines) = offline_list {
        license_product_item.insert_item(&LICENSES_TABLE.products_map_item.fields.offline_machines, offline_machines);
        *updated = true;
    }
}

/// Inserts strings, numbers, and bools into a hashmap.
macro_rules! insert_keys {
    ($stats_map:expr, $stats:expr, $keys:expr, ($($string:ident),*), ($($number:ident),*), ($($bools:ident),*)) => {
        $(
            $stats_map.insert_item(&$keys.$string, $stats.$string.clone());
        )*
        $(
            $stats_map.insert_item(&$keys.$number, $stats.$number.to_string());
        )*
        $(
            $stats_map.insert_item(&$keys.$bools, $stats.$bools);
        )*
    };
}

/// Inserts machine stats into a hashmap.
fn insert_stats(stats_map: &mut AttributeValueHashMap, stats: &Stats) {
    debug_log!("In insert_stats");
    insert_keys!(
        stats_map,
        stats,
        MACHINES_TABLE.stats.fields,
        // strings
        (cpu_model, cpu_vendor, os_name, users_language, display_language),
        // numbers
        (cpu_freq_mhz, num_logical_cores, num_physical_cores, ram_mb, page_size),
        // bools
        (is_64_bit, has_mmx, has_3d_now, has_fma3, has_fma4, has_sse, has_sse2, 
        has_sse3, has_ssse3, has_sse41, has_sse42, has_avx, has_avx2, 
        has_avx512f, has_avx512bw, has_avx512cd, has_avx512dq, has_avx512er, 
        has_avx512ifma, has_avx512pf, has_avx512vbmi, has_avx512vl, 
        has_avx512vpopcntdq, has_neon)
    );
}

fn insert_machine_into_machine_map(map: &mut AttributeValueHashMap, request: &LicenseActivationRequest) {
    debug_log!("In insert_machine_into_machine_map");
    let mach_map = if let Some(s) = &request.hardware_stats {
        let mut mach_map = AttributeValueHashMap::new(); 
        let mut truncated_name = s.os_name.clone();
        truncated_name.truncate(15);
        mach_map.insert_item(&MACHINE.os_name, truncated_name);
        mach_map.insert_item(&MACHINE.computer_name, s.computer_name.clone());
        mach_map
    } else {
        let mut mach_map = AttributeValueHashMap::new();
        mach_map.insert_item_into(&MACHINE.os_name, "Not provided");
        mach_map.insert_item_into(&MACHINE.computer_name, "Not provided");
        mach_map
    };
    map.insert_map(&request.machine_id, mach_map)
}

/// Initializes and updates a machine item.
/// 
/// Returns true if the table needs to be updated.
fn init_machine_item(request: &LicenseActivationRequest, machine_item: &mut AttributeValueHashMap, was_in_db: bool) -> Result<bool, ApiError> {
    debug_log!("In init_machine_item");
    match was_in_db {
        true => {
            if let Some(s) = &request.hardware_stats {
                debug_log!("Hardware stats were provided by the user");
                // hardware stats were provided by the user
                if machine_item.is_null(&MACHINES_TABLE.protobuf_data)? {
                    debug_log!("Inserting machine info into table");
                    // info needs to be entered
                    let mut stats_map = AttributeValueHashMap::new();
                    insert_stats(&mut stats_map, s);
                    machine_item.insert_item_into(&MACHINES_TABLE.stats, stats_map);
                    Ok(true)
                } else {
                    debug_log!("Checking if machine stats in the request and in the table are equal");
                    // stats have already been set; check if they are equal
                    let (mut existing_stats_map, mut_attribute_value) = machine_item.get_item_mut(&MACHINES_TABLE.stats)?;
                    let cpu = existing_stats_map.get_item(&MACHINES_TABLE.stats.fields.cpu_model)?;
                    let ram = existing_stats_map.get_item(&MACHINES_TABLE.stats.fields.ram_mb)?;
                    if cpu.ne(&s.cpu_model) || ram.ne(&s.ram_mb.to_string()) {
                        debug_log!("Machine stats were not the same; updating stats");
                        insert_stats(&mut existing_stats_map, s);
                        *mut_attribute_value = AttributeValue::M(existing_stats_map);
                        return Ok(true)
                    }
                    Ok(false)
                }
            } else {
                // stats have not been provided; erase stats and computer 
                // name
                debug_log!("Machine stats were not provided");
                if !machine_item.is_null(&MACHINES_TABLE.stats)? {
                    debug_log!("Overwriting existing stats with null values.");
                    machine_item.insert_null(&MACHINES_TABLE.stats);
                    machine_item.insert_null(&MACHINES_TABLE.protobuf_data);
                    return Ok(true)
                }
                Ok(false)
            }
        },
        false => {
            debug_log!("Machine was not already in the DB");
            // machine was not in the database
            if let Some(s) = &request.hardware_stats {
                debug_log!("Machine stats were provided by the user");
                // stats were provided by the user
                let mut stats_map = AttributeValueHashMap::new();
                insert_stats(&mut stats_map, &s);
                machine_item.insert_item(&MACHINES_TABLE.stats, stats_map);
            } else {
                debug_log!("Machine stats were not provided by the user; setting values to null");
                // stats were not provided by the user
                machine_item.insert_null(&MACHINES_TABLE.stats);
                machine_item.insert_null(&MACHINES_TABLE.protobuf_data);
            }
            Ok(true)
        }
    }
}

impl_function_handler!(
    LicenseActivationRequest, 
    LicenseActivationResponse, 
    ApiError, 
    false
);

async fn process_request<D: Digest + FixedOutput>(
    key_manager: &mut KeyManager, 
    request: &mut LicenseActivationRequest, 
    _hasher: D, 
    _signature: Vec<u8>
) -> Result<LicenseActivationResponse, ApiError> {
    debug_log!("Inside process_request");
    let client = init_dynamodb_client!();
    // there is no signature on this request
    let store_id = if let Ok(s) = key_manager.get_store_id() {
        s
    } else {
        return Err(ApiError::InvalidAuthentication)
    };

    let mut product_ids = Vec::new();
    debug_log!("Validating product IDs");
    for prod_id in &request.product_ids {
        if let Ok(p) = key_manager.validate_product_id(&prod_id, &store_id) {
            product_ids.push(p)
        } else {
            debug_log!("Found an invalid product id");
            return Err(ApiError::InvalidAuthentication)
        }
    }

    // check for offline license attempt
    let is_offline_attempt = request.license_code.to_lowercase().contains("offline");
    let (license_id, offline_license_code) = if is_offline_attempt {
        (key_manager.validate_license_code(&request.license_code, &store_id)?, &request.license_code[request.license_code.len()-4..])
    } else {
        (key_manager.validate_license_code(&request.license_code, &store_id)?, "")
    };
    debug_log!("License code has been successfully validated");

    // store_id, product_id, and license_id have been validated
    // now we need to check and validate with the database
    let mut request_items: HashMap<String, KeysAndAttributes> = HashMap::new();

    let mut store_item = AttributeValueHashMap::new();
    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
    store_item.insert_item(&STORES_TABLE.id, Blob::new(hashed_store_id.to_vec()));
    request_items.insert(
        STORES_TABLE.table_name.to_string(), 
        KeysAndAttributes::builder()
            .set_keys(Some(vec![store_item.clone()]))
            .consistent_read(false)
            .build()?
    );

    request_items.insert(
        METRICS_TABLE.table_name.to_string(),
        KeysAndAttributes::builder()
            .set_keys(Some(vec![store_item]))
            .consistent_read(false)
            .build()?
    );

    let mut license_item = AttributeValueHashMap::new();
    let hashed_license_id = salty_hash(&[store_id.binary_id.as_ref(), license_id.binary_id.as_ref()], &LICENSE_DB_SALT);
    license_item.insert_item(&LICENSES_TABLE.id, Blob::new(hashed_license_id.to_vec()));
    request_items.insert(
        LICENSES_TABLE.table_name.to_string(), 
        KeysAndAttributes::builder()
            .set_keys(Some(vec![license_item]))
            .consistent_read(true)
            .build()?
    );

    let mut machine_item = AttributeValueHashMap::new();
    machine_item.insert_item(&MACHINES_TABLE.id, request.machine_id.clone());
    request_items.insert(
        MACHINES_TABLE.table_name.to_string(), 
        KeysAndAttributes::builder()
            .set_keys(Some(vec![machine_item.clone()]))
            .consistent_read(false)
            .build()?
    );

    let batch_get = client.batch_get_item()
        .set_request_items(Some(request_items))
        .send()
        .await?;
    debug_log!("Performed batch_get_item");

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

    let mut metrics_item = if let Some(s) = tables.get(METRICS_TABLE.table_name) {
        if s.len() != 1 {
            return Err(ApiError::NotFound)
        }
        s[0].clone()
    } else {
        return Err(ApiError::NotFound)
    };

    let store_item_protobuf_data: StoreDbItem = key_manager.decrypt_db_proto(
        &STORES_TABLE.table_name, 
        store_id.binary_id.as_ref(), 
        store_item.get_item(&STORES_TABLE.protobuf_data)?.as_ref()
    )?;
    let store_configs = if let Some(c) = &store_item_protobuf_data.configs {
        c
    } else {
        return Err(ApiError::InvalidDbSchema("Missing store_configs".into()))
    };

    let store_product_info_map = &store_item_protobuf_data.product_ids;

    license_item = if let Some(l) = tables.get(LICENSES_TABLE.table_name) {
        if l.len() != 1 {
            return Err(ApiError::InvalidLicenseCode)
        }
        l[0].clone()
    } else {
        return Err(ApiError::InvalidLicenseCode)
    };

    let mut updated_license = false;

    // TODO: remove this if `regenerate_license_code` method will be better than
    // the `deactivate_machines` method

    // check if machine has been deactivated
    match license_item.get_item_mut(&LICENSES_TABLE.machines_to_deactivate) {
        Ok((mut deactivated_machines, mut_deactivated_machines)) => {
            if deactivated_machines.contains_key(&request.machine_id) {
                deactivated_machines.remove(&request.machine_id);
                *mut_deactivated_machines = AttributeValue::M(deactivated_machines);
                metrics_item.increase_number(&METRICS_TABLE.num_license_activations, 1)?;
                
                client.batch_write_item()
                    .request_items(
                        LICENSES_TABLE.table_name.to_string(), 
                        vec![
                            WriteRequest::builder()
                                .put_request(
                                    PutRequest::builder()
                                        .set_item(Some(license_item))
                                        .build()?
                                ).build()
                        ]
                    ).request_items(
                        METRICS_TABLE.table_name,
                        vec![
                            WriteRequest::builder()
                                .put_request(
                                    PutRequest::builder()
                                        .set_item(Some(metrics_item))
                                        .build()?
                                ).build()
                        ]
                    ).send()
                    .await?;
                return Err(ApiError::MachineDeactivated)
            }
            // deactivated machines list exists, but it did not contain the machine
            // remove machine if it has been there for over a year;
            // this can happen if a machine has broken or was sold or surplussed
            // yes, surplussed can be spelt with 2-3 `s`'s for some reason. It's
            // a weird word, more weird than "weird"
            let now = now_as_seconds();
            for (k, value) in deactivated_machines.to_owned() {
                let timestamp = value.as_n().expect("Deactivated Machines' values should be numbers").parse::<u64>()?;
                if now - timestamp > years_to_seconds(1) {
                    deactivated_machines.remove(&k);
                    updated_license = true;
                }
            }
            if updated_license {
                *mut_deactivated_machines = AttributeValue::M(deactivated_machines);
            }
        },
        Err(_) => ()
    }


    // update the machine item
    let machine_needs_update = if let Some(m) = tables.get(MACHINES_TABLE.table_name) {
        if m.len() != 1 {
            // make new machine item
            init_machine_item(&request, &mut machine_item, false)
        } else {
            init_machine_item(&request, &mut m[0].to_owned(), true)
        }
    } else {
        // make new machine item
        init_machine_item(&request, &mut machine_item, false)
    }?;

    // check offline code
    let (first_name, last_name, email) = check_licenses_db_proto(key_manager, is_offline_attempt, &offline_license_code, &license_item)?;

    let success_message = {
        let custom_message = license_item.get_item(&LICENSES_TABLE.custom_success_message)?;
        if custom_message.len() > 0 {
            custom_message.clone()
        } else {
            "1".to_string()
        }
    };
    
    // all items are present in the database
    // validate the license

    let (mut products_map, mut_products_map) = license_item.get_item_mut(&LICENSES_TABLE.products_map_item)?;
    let mut key_files: HashMap<String, LicenseKeyFile> = HashMap::new();
    let mut key_file_signatures: HashMap<String, Vec<u8>> = HashMap::new();
    let mut licensing_errors: HashMap<String, u32> = HashMap::new();

    for product_id in product_ids {
        debug_log!("In product_ids loop");
        let (mut license_product_map, mut_license_product_map) = products_map.get_mut_map_by_str(&product_id.encoded_id)?;
        let max_machines = license_product_map.get_item(&LICENSES_TABLE.products_map_item.fields.machines_allowed)?.parse::<usize>()?;
        let mut offline_machines_map = license_product_map.get_item(&LICENSES_TABLE.products_map_item.fields.offline_machines)?.to_owned();
        let mut online_machines_map = license_product_map.get_item(&LICENSES_TABLE.products_map_item.fields.online_machines)?.to_owned();
        let current_machine_count = offline_machines_map.keys().len() + online_machines_map.keys().len();
        
        let exists_in_machine_list = offline_machines_map.contains_key(&request.machine_id) || online_machines_map.contains_key(&request.machine_id);

        let expiry_time = license_product_map.get_item(&LICENSES_TABLE.products_map_item.fields.expiry_time).unwrap_or(&0.to_string()).parse::<u64>()?;
        let license_type = license_product_map.get_item(&LICENSES_TABLE.products_map_item.fields.license_type)?.to_lowercase();

        let license_is_active = license_product_map.get_item(&LICENSES_TABLE.products_map_item.fields.is_license_active)?;
        if !license_is_active {
            licensing_errors.insert(product_id.encoded_id, ApiError::LicenseNoLongerActive.get_licensing_error_number());
            continue;
        }
        debug_log!("Got license_is_active");

        let store_product_info = store_product_info_map.get(&product_id.encoded_id).expect("A validated store should be able to provide valid product IDs.");

        let mut key_file = LicenseKeyFile {
            product_id: product_id.encoded_id.clone(),
            product_version: store_product_info.version.clone(),
            license_code: request.license_code.clone(),
            license_type: license_type.clone(),
            machine_id: request.machine_id.clone(),
            timestamp: now_as_seconds(),
            expiration_timestamp: 0,
            check_back_timestamp: 0,
            message: "".into(),
            message_code: 1,
            post_expiration_error_code: 0,
        };
        
        // doing an OR operation instead of `.ne(license_types::PERPETUAL)` in case other license types get added
        let is_expiring = license_type.eq(license_types::TRIAL) || license_type.eq(license_types::SUBSCRIPTION);

        if is_expiring && expiry_time != 0 && expiry_time < SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() {
            // expiry time has been reached
            match license_type.as_str() {
                license_types::TRIAL => {
                    licensing_errors.insert(product_id.encoded_id, ApiError::TrialEnded.get_licensing_error_number());
                    continue;
                },
                license_types::SUBSCRIPTION => {
                    licensing_errors.insert(product_id.encoded_id, ApiError::LicenseNoLongerActive.get_licensing_error_number());
                    continue;
                },
                _ => unreachable!()
            }
        }
        let product_allows_offline = store_product_info.is_offline_allowed;
        
        // check machine lists
        if !exists_in_machine_list {
            debug_log!("Machine has not activated this license yet");
            if current_machine_count < max_machines {
                debug_log!("Enough room for this machine");
                // add 1 to total machines
                metrics_item.increase_number(&METRICS_TABLE.num_licensed_machines, 1)?;
                // success response, update tables
                if is_offline_attempt && product_allows_offline && license_type.eq(license_types::PERPETUAL) {
                    insert_machine_into_machine_map(&mut offline_machines_map, &request);
                    // add 1 to total offline machines
                    metrics_item.increase_number(&METRICS_TABLE.num_offline_machines, 1)?;
                    update_lists(&mut updated_license, &mut license_product_map, None, Some(offline_machines_map));
                } else {
                    insert_machine_into_machine_map(&mut online_machines_map, &request);
                    update_lists(&mut updated_license, &mut license_product_map, Some(online_machines_map), None);
                }
            } else {
                // machine limit reached
                licensing_errors.insert(product_id.encoded_id, ApiError::OverMaxMachines.get_licensing_error_number());
                continue;
            }
        } else {
            debug_log!("The machine has already activated this license previously");
            // machine exists in machine lists
            if is_offline_attempt && product_allows_offline && license_type.eq(license_types::PERPETUAL) {
                // remove machine from online machines list if it is there, then add it to offline machines list
                if online_machines_map.contains_key(&request.machine_id) {
                    online_machines_map.remove(&request.machine_id);
                    insert_machine_into_machine_map(&mut offline_machines_map, &request);
                    update_lists(&mut updated_license, &mut license_product_map,
                    Some(online_machines_map), Some(offline_machines_map));
                } 
            }
        }
        
        let now = now_as_seconds();
        let (local_expire_time, check_up_time) = match license_type.as_str() {
            license_types::TRIAL => {
                debug_log!("Handling trial license activation");
                let expire_time = if expiry_time == 0 {
                    // trial license is being activated; set the expiry time accordingly
                    let expire_time = now + (store_configs.trial_license_expiration_days as u64 * 24 * 60 * 60);
                    license_product_map.insert_item(
                        &LICENSES_TABLE.products_map_item.fields.expiry_time,
                        expire_time.to_string());
                    updated_license = true;
                    expire_time
                } else {
                    expiry_time
                };
                let mut check_up_time = now + (store_configs.trial_license_frequency_hours as u64 * 60 * 60);
                check_up_time = check_up_time.min(expire_time);
                key_file.post_expiration_error_code = ApiError::TrialEnded.to_string().parse::<u32>().unwrap();
                (expire_time, check_up_time)
            },
            license_types::SUBSCRIPTION => {
                debug_log!("Handling subscription license activation");
                let is_subscription_active = license_product_map.get_item(&LICENSES_TABLE.products_map_item.fields.is_subscription_active)?;
                if !is_subscription_active {
                    licensing_errors.insert(product_id.encoded_id, ApiError::LicenseNoLongerActive.get_licensing_error_number());
                    continue;
                }
                let mut expire_time = now + (store_configs.subscription_license_expiration_days as u64 * 24 * 60 * 60);
                let mut check_up_time = now + (store_configs.subscription_license_frequency_hours as u64 * 60 * 60);
                expire_time = expire_time.min(expiry_time);
                check_up_time = check_up_time.min(expire_time);
                key_file.post_expiration_error_code = ApiError::LicenseNoLongerActive.to_string().parse::<u32>().unwrap();
                (expire_time, check_up_time)
            },
            license_types::PERPETUAL => {
                debug_log!("Handling perpetual license activation");
                let expire_time = if is_offline_attempt && product_allows_offline {
                    u64::MAX
                } else {
                    now + (store_configs.perpetual_license_expiration_days as u64 * 24 * 60 * 60)
                };
                let mut check_up_time = now + (store_configs.perpetual_license_frequency_hours as u64 * 60 * 60);
                check_up_time = check_up_time.min(expire_time);
                (expire_time, check_up_time)
            },
            _ => {
                licensing_errors.insert(product_id.encoded_id, ApiError::InvalidDbSchema("Invalid license type".into()).get_licensing_error_number());
                continue;
            }
        };

        // update the map AttributeValues since we no longer have our get_mut methods
        *mut_license_product_map = AttributeValue::M(license_product_map);
        *mut_products_map = AttributeValue::M(products_map.clone());

        // set expire time and check-up time, then fill remaining fields
        key_file.expiration_timestamp = local_expire_time;
        key_file.check_back_timestamp = check_up_time;
        key_file.message = success_message.clone();

        key_files.insert(product_id.encoded_id.clone(), key_file.clone());
        debug_log!("Signing key file");
        let signature = key_manager.sign_key_file(&key_file.encode_length_delimited_to_vec(), &product_id)?;
        debug_log!("Successfully signed the key file");
        key_file_signatures.insert(product_id.encoded_id.clone(), signature);
    }

    let mut write_requests: HashMap<String, Vec<WriteRequest>> = HashMap::new();

    if updated_license {
        write_requests.insert(
            LICENSES_TABLE.table_name.to_string(),
            vec![WriteRequest::builder()
                .put_request(
                    PutRequest::builder()
                        .set_item(Some(license_item))
                        .build()?
                ).build()
            ]
        );
    }

    metrics_item.increase_number(&METRICS_TABLE.num_license_activations, 1)?;
    write_requests.insert(
        METRICS_TABLE.table_name.to_string(),
        vec![WriteRequest::builder()
            .put_request(
                PutRequest::builder()
                    .set_item(Some(metrics_item))
                    .build()?
            ).build()
        ]
    );

    if machine_needs_update {
        write_requests.insert(
            MACHINES_TABLE.table_name.to_string(),
            vec![WriteRequest::builder()
                .put_request(
                    PutRequest::builder()
                        .set_item(Some(machine_item))
                        .build()?
                ).build()
            ]
        );
    }

    client.batch_write_item()
        .set_request_items(Some(write_requests))
        .send()
        .await?;

    let response = LicenseActivationResponse {
        key_files,
        key_file_signatures,
        licensing_errors,
        customer_first_name: first_name,
        customer_last_name: last_name,
        customer_email: email,
    };

    Ok(response)
}