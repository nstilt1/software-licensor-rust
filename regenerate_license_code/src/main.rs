use http_private_key_manager::prelude::days_to_seconds;
use http_private_key_manager::private_key_generator::ecdsa::VerifyingKey;
use proto::protos::regenerate_license_code::RegenerateLicenseCodeRequest;
use utils::aws_config::meta::region::RegionProviderChain;
use utils::aws_sdk_dynamodb::types::{DeleteRequest, KeysAndAttributes, PutRequest, WriteRequest};
use utils::aws_sdk_dynamodb::Client;
use utils::crypto::p384::ecdsa::Signature;
use utils::dynamodb::maps::Maps;
use utils::get_license::{construct_get_license_response_from_license_item, query_dynamodb_for_license_item_primary_key};
use utils::init_license::init_license;
use utils::prelude::proto::protos::get_license_request::GetLicenseResponse;
use utils::{now_as_seconds, prelude::*};
use utils::tables::licenses::LICENSES_TABLE;
use utils::tables::metrics::METRICS_TABLE;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};

impl_function_handler!(
    RegenerateLicenseCodeRequest, 
    GetLicenseResponse, 
    ApiError, 
    false
);

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut RegenerateLicenseCodeRequest, hasher: D, signature: Vec<u8>) -> Result<GetLicenseResponse, ApiError> {
    let client = init_dynamodb_client!();
    
    let store_id = key_manager.get_store_id()?;

    let mut old_license_item = query_dynamodb_for_license_item_primary_key(&client, &store_id, &request.user_id).await?;

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
                .keys(old_license_item)
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

    old_license_item = match tables.get(LICENSES_TABLE.table_name) {
        Some(v) => v[0].clone(),
        None => return Err(ApiError::NotFound)
    };

    let mut old_license_key = AttributeValueHashMap::new();
    old_license_key.insert_item(
        LICENSES_TABLE.id,
        old_license_item.get_item(LICENSES_TABLE.id)?.to_owned()
    );

    match old_license_item.get_item(LICENSES_TABLE.last_license_regen) {
        Ok(v) => {
            let cooled_down_time = v.parse::<u64>()? + days_to_seconds(14);
            if now_as_seconds() < cooled_down_time {
                return Err(ApiError::InvalidRequest("A fortnight must pass between license regeneration requests".into()))
            }
        },
        Err(_) => ()
    }

    metrics_item = match tables.get(METRICS_TABLE.table_name) {
        Some(v) => v[0].clone(),
        None => return Err(ApiError::NotFound)
    };

    let mut new_products_map = old_license_item.get_item(LICENSES_TABLE.products_map_item)?.clone();

    let product_keys: Vec<String> = new_products_map.keys().cloned().collect();

    // insert empty online_machines map into each product's license info
    for k in product_keys.iter() {
        let mut product_map = new_products_map.get_map_by_str(k)?.clone();

        product_map.insert_item(LICENSES_TABLE.products_map_item.fields.online_machines, AttributeValueHashMap::new());
        new_products_map.insert_map(&k, product_map);
    }

    let mut new_license_item = old_license_item.clone();
    new_license_item.insert_item(LICENSES_TABLE.products_map_item, new_products_map);
    new_license_item.insert_item(LICENSES_TABLE.last_license_regen, now_as_seconds().to_string());

    init_license(&client, key_manager, None, &mut new_license_item, &store_id).await?;

    let resp = construct_get_license_response_from_license_item(key_manager, &new_license_item)?;

    metrics_item.increase_number(&METRICS_TABLE.num_machine_deactivations, 1)?;
    client.batch_write_item()
        .request_items(
            LICENSES_TABLE.table_name, 
            vec![
                WriteRequest::builder()
                    .put_request(
                        PutRequest::builder()
                            .set_item(Some(new_license_item))
                            .build()?
                    ).build(),
                WriteRequest::builder()
                    .delete_request(
                        DeleteRequest::builder()
                            .set_key(Some(old_license_key))
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

    Ok(resp)
}