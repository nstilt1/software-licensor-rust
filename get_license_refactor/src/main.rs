//! A plugin creation API method for a licensing service.

use std::collections::HashMap;
use utils::aws_config::meta::region::RegionProviderChain;
use utils::aws_sdk_dynamodb::types::{AttributeValue, Select};
use utils::aws_sdk_dynamodb::Client;
use utils::crypto::p384::ecdsa::Signature;
use utils::prelude::proto::protos::license_db_item::LicenseDbItem;
use utils::prelude::proto::protos::get_license_request::{GetLicenseRequest, GetLicenseResponse, LicenseInfo, Machine};
use utils::prelude::*;
use utils::tables::licenses::LICENSES_TABLE;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};

impl_function_handler!(
    GetLicenseRequest, 
    GetLicenseResponse, 
    ApiError, 
    false
);

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut GetLicenseRequest, hasher: D, signature: Vec<u8>) -> Result<GetLicenseResponse, ApiError> {
    debug_log!("Inside process_request");
    // the StoreId has already been verified in `decrypt_and_hash_request()` but
    // we still need to verify the signature against the public key in the db
    let client = init_dynamodb_client!();
    
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
    // get license item from db
    let secondary_index = salty_hash(&[store_id.binary_id.as_ref(), 
        request.user_id.as_bytes()], &LICENSE_DB_SALT).to_vec();
    let query = client.query()
        .table_name(LICENSES_TABLE.table_name)
        .index_name(LICENSES_TABLE.hashed_store_id_and_user_id.index_name)
        .key_condition_expression("#user_id_hash = :key_value")
        .expression_attribute_names("#user_id_hash", LICENSES_TABLE.hashed_store_id_and_user_id.item.key)
        .expression_attribute_values(":key_value", AttributeValue::B(Blob::new(secondary_index)))
        .select(Select::AllProjectedAttributes)
        .send()
        .await?;

    let mut license_item: AttributeValueHashMap;
    if let Some(v) = query.items {
        if v.len() == 0 {
            return Err(ApiError::NotFound)
        }
        license_item = v[0].clone();
        license_item.remove(LICENSES_TABLE.hashed_store_id_and_user_id.item.key);
    } else {
        return Err(ApiError::NotFound)
    }
    let get_output = client.get_item()
        .table_name(LICENSES_TABLE.table_name)
        .set_key(Some(license_item))
        .consistent_read(false)
        .send()
        .await?;
    
    license_item = match get_output.item {
        Some(x) => x,
        None => return Err(ApiError::NotFound)
    };
    
    let (license_code, offline_code) = {
        let license_protobuf: LicenseDbItem = key_manager.decrypt_db_proto(
            &LICENSES_TABLE.table_name, 
            license_item.get_item(LICENSES_TABLE.id)?.as_ref(),
            license_item.get_item(LICENSES_TABLE.protobuf_data)?.as_ref()
        )?;
        let license_code = bytes_to_license(&license_protobuf.license_id);
        (license_code, license_protobuf.offline_secret.to_string())
    };
    
    let mut licensed_products: HashMap<String, LicenseInfo> = HashMap::new();
    let products_map = license_item.get_item(LICENSES_TABLE.products_map_item)?;
    for key in products_map.keys() {
        let product = products_map.get_map_by_str(key.as_str())?;
        let offline_machines_map = product.get_item(LICENSES_TABLE.products_map_item.fields.offline_machines)?;
        let online_machines_map = product.get_item(LICENSES_TABLE.products_map_item.fields.online_machines)?;
        let machine_limit = product.get_item(LICENSES_TABLE.products_map_item.fields.machines_allowed)?.parse::<u32>()?;
        let license_type = product.get_item(LICENSES_TABLE.products_map_item.fields.license_type)?.to_string();
        let mut offline_machines: Vec<Machine> = Vec::with_capacity(offline_machines_map.len());
        let mut online_machines: Vec<Machine> = Vec::with_capacity(online_machines_map.len());
        let workspace = &mut [(offline_machines_map, &mut offline_machines), (online_machines_map, &mut online_machines)];
        for (map, vec) in workspace.iter_mut() {
            for k in map.keys() {
                let id = k;
                let machine = map.get_map_by_str(k)?;
                let os = machine.get_item(LICENSES_TABLE.products_map_item.fields.offline_machines.fields.os_name)?;
                let computer_name = machine.get_item(LICENSES_TABLE.products_map_item.fields.offline_machines.fields.computer_name)?;
                vec.push(Machine { 
                    id: id.to_string(), 
                    os: os.to_string(), 
                    computer_name: computer_name.to_string() 
                });
            }
        }
        let expiration = if license_type.eq(license_types::SUBSCRIPTION) || license_type.eq(license_types::TRIAL) {
            match product.get_item(LICENSES_TABLE.products_map_item.fields.expiry_time) {
                Ok(v) => v,
                Err(_) => "Not yet set"
            }
        } else {
            "No expiration"
        };
        licensed_products.insert(key.to_string(), LicenseInfo {
            offline_machines, 
            online_machines, 
            machine_limit, 
            license_type,
            expiration_or_renewal: expiration.to_string()
        });
    }
    let response = GetLicenseResponse {
        licensed_products,
        license_code,
        offline_code,
    };

    Ok(response)
}