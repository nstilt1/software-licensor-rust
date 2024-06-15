//! A store registration API method for a licensing service.
use std::collections::HashMap;
use utils::crypto::p384::ecdsa::Signature;
use utils::now_as_seconds;
use proto::protos::store_db_item::StoreDbItem;
use utils::prelude::proto::protos::store_db_item;
use utils::prelude::*;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use proto::protos::register_store_request::{RegisterStoreRequest, RegisterStoreResponse};
use utils::aws_sdk_dynamodb::Client;
use utils::aws_config::meta::region::RegionProviderChain;

impl_function_handler!(
    RegisterStoreRequest, 
    RegisterStoreResponse, 
    ApiError, 
    true
);

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut RegisterStoreRequest, hasher: D, signature: Vec<u8>) -> Result<RegisterStoreResponse, ApiError> {
    debug_log!("In process_request");
    if request.contact_first_name.len() < 2 || 
        request.contact_last_name.len() < 2 ||
        request.contact_email.len() < 2 ||
        request.store_name.len() < 2 ||
        request.store_url.len() < 2 || 
        request.state.len() < 2 ||
        request.country.len() < 2 
    {
        return Err(ApiError::InvalidRequest("Please provide accurate information".into()))
    }

    let client = init_dynamodb_client!();

    debug_log!("Made it past initial validation");
    // verify public key before storing info in the database to ensure that they know how to format requests and that everything is working properly
    // with an established client, we will need to fetch the public key 
    // from the database to verify the signature instead of this
    let pubkey = PublicKey::from_sec1_bytes(&request.public_signing_key)?;
    debug_log!("Initialized pubkey");
    let verifier = VerifyingKey::from(pubkey);
    let signature: Signature = Signature::from_bytes(signature.as_slice().try_into().unwrap())?;
    debug_log!("Initialized signature");
    verifier.verify_digest(hasher, &signature)?;

    debug_log!("Verfied signature");

    // generate store ID and make sure it isn't already in the database
    let mut store_id = key_manager.get_store_id()?;
    debug_log!("Got the store ID");

    let mut store_item = AttributeValueHashMap::new();

    loop {
        let hashed_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
        
        store_item.insert_item(STORES_TABLE.id, Blob::new(hashed_id.to_vec()));
        
        let get_output = client.get_item()
            .table_name(STORES_TABLE.table_name)
            .consistent_read(false)
            .set_key(Some(store_item.clone()))
            .send()
            .await?;

        if get_output.item.is_some() {
            store_id = key_manager.regenerate_store_id()?;
        } else {
            break;
        }
    }
    debug_log!("Picked a store ID");
    
    // a solid store_id has been found, most likely with one try. Now, we
    // will create the database item
    let configs = if let Some(c) = &request.configs {
        // validate configs with bounds
        let mut c = c.clone();
        macro_rules! bound {
            ($value:expr, $lower_bound:literal) => {
                $value = $value.max($lower_bound)
            };
        }
        bound!(c.max_machines_per_license, 3);
        bound!(c.offline_license_frequency_hours, 300);
        bound!(c.perpetual_license_expiration_days, 24);
        bound!(c.perpetual_license_frequency_hours, 300);
        bound!(c.subscription_license_expiration_days, 30);
        bound!(c.subscription_license_expiration_leniency_hours, 6);
        bound!(c.subscription_license_frequency_hours, 16);
        bound!(c.trial_license_expiration_days, 3);
        bound!(c.trial_license_frequency_hours, 72);
        c
    } else {
        return Err(ApiError::InvalidRequest("Configs are required".into()))
    };

    let proto = StoreDbItem {
        contact_first_name: request.contact_first_name.to_owned(),
        contact_last_name: request.contact_last_name.to_owned(),
        store_name: request.store_name.to_owned(),
        store_url: request.store_url.to_owned(),
        email: request.contact_email.to_owned(),
        discord_username: request.discord_username.to_owned(),
        state: request.state.to_owned(),
        country: request.country.to_owned(),
        product_ids: HashMap::new(),
        configs: Some(store_db_item::Configs {
            offline_license_frequency_hours: configs.offline_license_frequency_hours,
            perpetual_license_expiration_days: configs.perpetual_license_expiration_days,
            perpetual_license_frequency_hours: configs.perpetual_license_frequency_hours,
            subscription_license_expiration_days: configs.subscription_license_expiration_days,
            subscription_license_expiration_leniency_hours: configs.subscription_license_expiration_leniency_hours,
            subscription_license_frequency_hours: configs.subscription_license_frequency_hours,
            trial_license_expiration_days: configs.trial_license_expiration_days,
            trial_license_frequency_hours: configs.trial_license_frequency_hours,
        })
    };
    
    let encrypted_protobuf = key_manager.encrypt_db_proto(STORES_TABLE.table_name, store_id.binary_id.as_ref(), &proto)?;
    debug_log!("Encrypted store db item");
    store_item.insert_item(STORES_TABLE.protobuf_data, Blob::new(encrypted_protobuf));

    store_item.insert_item(STORES_TABLE.public_key, Blob::new(request.public_signing_key.to_vec()));
    store_item.insert_item(STORES_TABLE.registration_date, now_as_seconds().to_string());

    client.put_item()
        .table_name(STORES_TABLE.table_name)
        .set_item(Some(store_item))
        .send()
        .await?;
    
    debug_log!("Put store item in database");
    
    let response = RegisterStoreResponse {
        store_id: store_id.encoded_id,
    };
    Ok(response)
}