use std::collections::HashMap;

use aws_sdk_dynamodb::{types::{AttributeValue, Select}, Client};
use aws_sdk_s3::primitives::Blob;
use http_private_key_manager::Id;
use proto::protos::{get_license_request::{GetLicenseResponse, LicenseInfo, Machine}, license_db_item::LicenseDbItem};

use crate::{prelude::{bytes_to_license, license_types, salty_hash, ApiError, AttributeValueHashMap, DigitalLicensingThemedKeymanager, ItemIntegration, KeyManager, StoreId, LICENSE_DB_SALT}, tables::licenses::LICENSES_TABLE};

/// Performs a query to DynamoDB to retrieve the primary key of a user's license.
#[inline]
pub async fn query_dynamodb_for_license_item_primary_key(client: &Client, store_id: &Id<StoreId>, user_id: &str) -> Result<AttributeValueHashMap, ApiError> {
    let secondary_index = salty_hash(&[store_id.binary_id.as_ref(), user_id.as_bytes()], &LICENSE_DB_SALT).to_vec();
    let query = client.query()
        .table_name(LICENSES_TABLE.table_name)
        .index_name(LICENSES_TABLE.hashed_store_id_and_user_id.index_name)
        .key_condition_expression("#user_id_hash = :key_value")
        .expression_attribute_names("#user_id_hash", LICENSES_TABLE.hashed_store_id_and_user_id.item.key)
        .expression_attribute_values(":key_value", AttributeValue::B(Blob::new(secondary_index)))
        .select(Select::AllProjectedAttributes)
        .send()
        .await?;

    match query.items {
        Some(v) => {
            if v.len() != 1 {
                return Err(ApiError::NotFound)
            }
            // remove the Global Secondary Index so that we can do a batch-get-item with the result
            // - the secondary index only copies the keys so as to not use a ton of space in dynamodb
            let mut result = v[0].clone();
            result.remove(LICENSES_TABLE.hashed_store_id_and_user_id.item.key);
            Ok(result)
        },
        None => return Err(ApiError::NotFound)
    }
}

/// Constructs a GetLicenseResponse from a Licenses table item
#[inline]
pub fn construct_get_license_response_from_license_item(key_manager: &mut KeyManager, license_item: &AttributeValueHashMap) -> Result<GetLicenseResponse, ApiError> {
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
    Ok(GetLicenseResponse {
        licensed_products,
        license_code,
        offline_code,
    })
}