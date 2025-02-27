use std::env;

use serde::{Deserialize, Serialize};
use utils::crypto::{init_key_manager, salty_hash, DigitalLicensingThemedKeymanager, STORE_DB_SALT};
use utils::prelude::lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use utils::tables::stores::STORES_TABLE;
use utils::{aws_config, debug_log, serde_json};
use utils::aws_sdk_cognitoidentityprovider::Client as CognitoClient;
use utils::prelude::proto::protos::create_store_request::StoreDbItem;
use utils::prelude::{AttributeValueHashMap, Blob, ItemIntegration, Message};
use utils::aws_sdk_dynamodb::Client as DbClient;

fn error_resp(status: u16, contents: &str) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(status)
        .body(Body::Text(contents.to_string()))
        .unwrap())
}

#[derive(Serialize, Deserialize, Debug)]
struct UpdateSettingsRequest {
    store_id: String,
    configs: Configs,
}

#[derive(Serialize, Deserialize, Debug)]
struct UpdateSettingResponse {
    configs: Configs,
}

#[derive(Serialize, Deserialize, Debug)]
struct Configs {
    offline_license_frequency_hours: u32,
    perpetual_license_expiration_days: u32,
    perpetual_license_frequency_hours: u32,
    subscription_license_expiration_days: u32,
    subscription_license_expiration_leniency_hours: u32,
    subscription_license_frequency_hours: u32,
    trial_license_expiration_days: u32,
    trial_license_frequency_hours: u32,
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    // Extract some useful information from the request
    let request_context = event.request_context();
    let user_sub = request_context
        .authorizer()
        .and_then(|auth| auth.jwt.clone())
        .and_then(|jwt| Some(jwt.claims))
        .and_then(|claims| claims.get("sub").cloned())
        .unwrap_or_default();

    if user_sub.is_empty() {
        return error_resp(401, "Unauthorized: Missing sub claim")
    }

    let body = match event.body() {
        Body::Text(b) => b,
        _ => return error_resp(400, "Invalid request body")
    };

    let request: UpdateSettingsRequest = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return error_resp(400, &format!("Invalid request body: {:?}", e))
    };

    let config = aws_config::load_from_env().await;
    let cognito_client = CognitoClient::new(&config);

    let user_pool_id = env::var("USER_POOL_ID").expect("USER_POOL_ID not set");
    let username = &user_sub;

    let user_data = cognito_client
        .admin_get_user()
        .user_pool_id(&user_pool_id)
        .username(username)
        .send()
        .await?;

    let mut store_keys: Vec<String> = vec![];
    if let Some(attributes) = user_data.user_attributes {
        for attr in attributes {
            if attr.name() == "custom:store_keys" {
                if let Some(value) = attr.value {
                    if let Ok(parsed) = serde_json::from_str::<Vec<String>>(&value) {
                        store_keys = parsed;
                    }
                }
            }
        }
    }

    if !store_keys.contains(&request.store_id) {
        return error_resp(403, "That store id does not belong to you.");
    }

    let mut key_manager = init_key_manager(None, None);
    
    let configs = if let Some(mut c) = Some(request.configs) {
        // validate configs with bounds
        macro_rules! bound {
            ($value:expr, $lower_bound:literal) => {
                $value = $value.max($lower_bound)
            };
        }
        bound!(c.offline_license_frequency_hours, 500);
        bound!(c.perpetual_license_expiration_days, 30);
        bound!(c.perpetual_license_frequency_hours, 16);
        bound!(c.subscription_license_expiration_days, 30);
        bound!(c.subscription_license_expiration_leniency_hours, 6);
        bound!(c.subscription_license_frequency_hours, 16);
        bound!(c.trial_license_expiration_days, 3);
        bound!(c.trial_license_frequency_hours, 72);
        c
    } else {
        return error_resp(400, "Missing conf");
    };

    // retrieve StoreDbItem
    let store_id = match key_manager.validate_store_id(&request.store_id) {
        Ok(v) => v,
        Err(_) => return error_resp(400, "Invalid store id")
    };

    let mut store_item = AttributeValueHashMap::with_capacity(1);
    store_item.insert_item(&STORES_TABLE.id, Blob::new(
        salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT).to_vec()
    ));
    let db_client = DbClient::new(&config);
    let get_output = db_client.get_item()
        .table_name(STORES_TABLE.table_name)
        .consistent_read(false)
        .set_key(Some(store_item))
        .send()
        .await?;

    if get_output.item.is_none() {
        return error_resp(400, "Store not found")
    }

    store_item = get_output.item.unwrap();

    let encrypted_proto = store_item.get_item(&STORES_TABLE.protobuf_data)?;

    let mut proto: StoreDbItem = key_manager.decrypt_db_proto(&STORES_TABLE.table_name, store_id.binary_id.as_ref(), encrypted_proto.as_ref())?;
    
    proto.configs = Some(utils::prelude::proto::protos::create_store_request::Configs { 
        offline_license_frequency_hours: configs.offline_license_frequency_hours, 
        perpetual_license_expiration_days: configs.perpetual_license_expiration_days, 
        perpetual_license_frequency_hours: configs.perpetual_license_frequency_hours, 
        subscription_license_expiration_days: configs.subscription_license_expiration_days, 
        subscription_license_expiration_leniency_hours: configs.subscription_license_expiration_leniency_hours, 
        subscription_license_frequency_hours: configs.subscription_license_frequency_hours, 
        trial_license_expiration_days: configs.trial_license_expiration_days, 
        trial_license_frequency_hours: configs.trial_license_frequency_hours 
    });

    let encrypted_protobuf = key_manager.encrypt_db_proto(
        &STORES_TABLE.table_name, 
        store_id.binary_id.as_ref(), 
        &proto
    )?;

    debug_log!("Encrypted store db item");

    store_item.insert_item(&STORES_TABLE.protobuf_data, Blob::new(encrypted_protobuf));

    // update StoreDbItem
    db_client.put_item()
        .table_name(STORES_TABLE.table_name)
        .set_item(Some(store_item))
        .send()
        .await?;

    debug_log!("Put store item in database");

    let response_message = UpdateSettingResponse {
        configs
    };

    let resp = serde_json::to_string(&response_message).expect("Failed to serialize JSON response");

    Ok(Response::builder()
        .status(200)
        .header("Content-type", "application/json")
        .body(Body::Text(resp))
        .unwrap())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}
