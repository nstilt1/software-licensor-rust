use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::primitives::Blob;
use http_private_key_manager::{prelude::rand_core::RngCore, Id};
use proto::protos::{create_license_request::CreateLicenseRequest, license_db_item::LicenseDbItem};

use crate::{prelude::{salty_hash, ApiError, AttributeValueHashMap, DigitalLicensingThemedKeymanager, ItemIntegration, KeyManager, StoreId, LICENSE_DB_SALT}, tables::licenses::LICENSES_TABLE};

/// Creates a license code and offline code, and initializes a license.
/// 
/// If `request` is none, the license is being regenerated, and this will 
/// decrypt and re-encrypt the LicenseDbInfo.
#[inline]
pub async fn init_license(
    client: &Client, 
    key_manager: &mut KeyManager, 
    hashed_user_id_and_request: Option<(&[u8], &CreateLicenseRequest)>, 
    license_item: &mut AttributeValueHashMap, 
    store_id: &Id<StoreId>,
) -> Result<(String, String), ApiError> {
    let (license_code, primary_index) = 
    // ensure an unused license code is created
    loop {
        let mut license_check_item = AttributeValueHashMap::new();
        let license_code = key_manager.generate_license_code(&store_id)?;
        let primary_index = salty_hash(&[store_id.binary_id.as_ref(), license_code.binary_id.as_ref()], &LICENSE_DB_SALT);
        license_check_item.insert_item(LICENSES_TABLE.id, Blob::new(primary_index.to_vec()));
        
        let get_item = client.get_item()
            .consistent_read(false)
            .table_name(LICENSES_TABLE.table_name)
            .set_key(Some(license_check_item.clone()))
            .send()
            .await?;
        if get_item.item.is_none() {
            break (license_code, primary_index);
        }
    };
    
    let offline_secret_u16 = key_manager.rng.next_u32() as u16;
    let offline_secret = format!("{:x}", offline_secret_u16);

    if let Some((hashed_user_id, request)) = hashed_user_id_and_request {
        // creating a new license
        license_item.insert_item(LICENSES_TABLE.hashed_store_id_and_user_id, Blob::new(hashed_user_id));
        license_item.insert_item_into(LICENSES_TABLE.custom_success_message, request.custom_success_message.clone());
        license_item.insert_item(LICENSES_TABLE.email_hash, Blob::new(salty_hash(&[request.customer_email.as_bytes()], &LICENSE_DB_SALT).to_vec()));
        license_item.insert_item(LICENSES_TABLE.products_map_item, AttributeValueHashMap::new());
        let protobuf_data = LicenseDbItem {
            license_id: license_code.binary_id.as_ref().to_vec(),
            customer_first_name: request.customer_first_name.clone(),
            customer_last_name: request.customer_last_name.clone(),
            customer_email: request.customer_email.clone(),
            offline_secret: offline_secret.clone(),
        };
        let encrypted = key_manager.encrypt_db_proto(
            LICENSES_TABLE.table_name, 
            &primary_index.as_ref(), 
            &protobuf_data
        )?;
        license_item.insert_item(LICENSES_TABLE.protobuf_data, Blob::new(encrypted));
    } else {
        // regenerating the license
        let mut decrypted_proto: LicenseDbItem = key_manager.decrypt_db_proto(
            &LICENSES_TABLE.table_name,
            license_item.get_item(LICENSES_TABLE.id)?.as_ref(),
            license_item.get_item(LICENSES_TABLE.protobuf_data)?.as_ref()
        )?;
        decrypted_proto.offline_secret = offline_secret.clone();
        let encrypted = key_manager.encrypt_db_proto(
            &LICENSES_TABLE.table_name, 
            &primary_index.as_ref(), 
            &decrypted_proto
        )?;
        license_item.insert_item(LICENSES_TABLE.protobuf_data, Blob::new(encrypted));
    }
    license_item.insert_item(LICENSES_TABLE.id, Blob::new(primary_index.to_vec()));

    Ok((license_code.encoded_id, offline_secret))
}