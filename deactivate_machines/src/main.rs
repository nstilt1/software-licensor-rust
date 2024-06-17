use http_private_key_manager::private_key_generator::ecdsa::VerifyingKey;
use proto::protos::deactivate_machines::DeactivateMachinesRequest;
use utils::aws_config::meta::region::RegionProviderChain;
use utils::aws_sdk_dynamodb::types::{AttributeValue, KeysAndAttributes, PutRequest, WriteRequest};
use utils::aws_sdk_dynamodb::Client;
use utils::crypto::p384::ecdsa::Signature;
use utils::dynamodb::maps::Maps;
use utils::get_license::{construct_get_license_response_from_license_item, query_dynamodb_for_license_item_primary_key};
use utils::prelude::proto::protos::get_license_request::GetLicenseResponse;
use utils::{now_as_seconds, prelude::*};
use utils::tables::licenses::LICENSES_TABLE;
use utils::tables::metrics::METRICS_TABLE;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};

impl_function_handler!(
    DeactivateMachinesRequest, 
    GetLicenseResponse, 
    ApiError, 
    false
);

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut DeactivateMachinesRequest, hasher: D, signature: Vec<u8>) -> Result<GetLicenseResponse, ApiError> {
    let client = init_dynamodb_client!();
    
    let store_id = key_manager.get_store_id()?;

    let mut license_item = query_dynamodb_for_license_item_primary_key(&client, &store_id, &request.user_id).await?;

    let hashed_store_id = salty_hash(&[key_manager.get_store_id()?.binary_id.as_ref()], &STORE_DB_SALT);

    let mut store_item = AttributeValueHashMap::new();
    store_item.insert_item(STORES_TABLE.id, Blob::new(hashed_store_id.to_vec()));

    let mut metrics_item = store_item.clone();

    let batch_get = client.batch_get_item()
        .request_items(
            STORES_TABLE.table_name, 
            KeysAndAttributes::builder()
                .consistent_read(false)
                .keys(store_item)
                .build()?
        ).request_items(
            METRICS_TABLE.table_name, 
            KeysAndAttributes::builder()
                .consistent_read(false)
                .keys(metrics_item)
                .build()?
        ).request_items(
            LICENSES_TABLE.table_name, 
            KeysAndAttributes::builder()
                .consistent_read(false)
                .keys(license_item)
                .build()?
        ).send()
        .await?;

    let tables = match batch_get.responses {
        Some(v) => v,
        None => return Err(ApiError::NotFound)
    };

    store_item = match tables.get(STORES_TABLE.table_name) {
        Some(v) => v[0].clone(),
        None => return Err(ApiError::NotFound)
    };

    // verify signature
    let public_key = store_item.get_item(STORES_TABLE.public_key)?;
    let pubkey = PublicKey::from_sec1_bytes(&public_key.as_ref())?;
    let verifier = VerifyingKey::from(pubkey);
    let signature: Signature = Signature::from_bytes(signature.as_slice().try_into().unwrap())?;
    verifier.verify_digest(hasher, &signature)?;

    license_item = match tables.get(LICENSES_TABLE.table_name) {
        Some(v) => v[0].clone(),
        None => return Err(ApiError::NotFound)
    };

    metrics_item = match tables.get(METRICS_TABLE.table_name) {
        Some(v) => v[0].clone(),
        None => return Err(ApiError::NotFound)
    };

    let mut products_map = license_item.get_item(LICENSES_TABLE.products_map_item)?.clone();

    // the client side code should ensure that there's a valid machine being removed, but just in case the machine is there, we will check
    let mut removed_machines = false;

    let product_keys: Vec<String> = products_map.keys().cloned().collect();

    let mut machines_to_deactivate = match license_item.get_item(LICENSES_TABLE.machines_to_deactivate) {
        Ok(v) => {
            v.to_owned()
        },
        Err(_) => {
            // the map did not exist, make a new one
            AttributeValueHashMap::with_capacity(request.machine_ids.len())
        }
    };

    for k in product_keys.iter() {
        let mut product_map = products_map.get_map_by_str(k)?.clone();
        let mut online_machines = product_map.get_item(LICENSES_TABLE.products_map_item.fields.online_machines)?.to_owned();
        
        let mut found_online_machine_in_product = false;
        for machine in request.machine_ids.iter() {
            if online_machines.contains_key(machine) {
                online_machines.remove(machine);
                removed_machines = true;
                found_online_machine_in_product = true;
                if !machines_to_deactivate.contains_key(machine) {
                    machines_to_deactivate.insert(
                        machine.to_string(), 
                        AttributeValue::N(now_as_seconds().to_string())
                    );
                }
            }
        }
        if found_online_machine_in_product {
            product_map.insert_item(LICENSES_TABLE.products_map_item.fields.online_machines, online_machines);
            products_map.insert_map(&k, product_map);
        }
    }

    let resp = construct_get_license_response_from_license_item(key_manager, &license_item)?;

    metrics_item.increase_number(&METRICS_TABLE.num_machine_deactivations, 1)?;
    if removed_machines {
        license_item.insert_item(LICENSES_TABLE.products_map_item, products_map);
        license_item.insert_item(LICENSES_TABLE.machines_to_deactivate, machines_to_deactivate);

        client.batch_write_item()
            .request_items(
                LICENSES_TABLE.table_name, 
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
    } else {
        client.put_item()
            .table_name(METRICS_TABLE.table_name)
            .set_item(Some(metrics_item))
            .send()
            .await?;
    }
    Ok(resp)
}