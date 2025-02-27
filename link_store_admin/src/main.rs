use std::collections::HashMap;

use utils::{
    aws_config, aws_sdk_cognitoidentityprovider::{types::AttributeType, Client as CognitoClient}, aws_sdk_dynamodb::{types::KeysAndAttributes, Client as DbClient}, crypto::{init_key_manager, salty_hash, DigitalLicensingThemedKeymanager, STORE_DB_SALT}, prelude::{
        lambda_http::{
            run, service_fn, tracing, Body, Error, Request, RequestExt, Response
        }, proto::protos::create_store_request::StoreDbItem, AttributeValueHashMap, Blob, ItemIntegration
    }, serde_json, tables::{metrics::METRICS_TABLE, stores::STORES_TABLE}
};

fn error_resp(status: u16, contents: &str) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(status)
        .body(Body::Text(contents.to_string()))
        .unwrap())
}
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
struct LinkStoreRequest {
    store_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct LinkStoreResponse {
    metrics: StoreMetricsJSON,
    configs: Configs
}

#[derive(Serialize, Deserialize, Debug, Default)]
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

#[derive(Serialize, Deserialize, Debug, Default)]
struct StoreMetricsJSON {
    num_products: u32,
    num_licenses: u32,
    num_licensed_machines: u32,
    num_offline_machines: u32,
    num_online_machines: u32,
    num_license_activations: u32,
    num_license_regens: u32,
    num_machine_deactivations: u32,
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
        return error_resp(401, "Unauthorized: Missing sub claim");
    }

    let body = match event.body() {
        Body::Text(b) => b,
        _ => return error_resp(400, "Invalid request body")
    };

    let request: LinkStoreRequest = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return error_resp(400, &format!("Invalid request body: {:?}", e))
    };

    let config = aws_config::load_from_env().await;
    let cognito_client = CognitoClient::new(&config);
    let db_client = DbClient::new(&config);

    let user_pool_id = std::env::var("USER_POOL_ID").expect("USER_POOL_ID not set");
    let username = &user_sub;

    let user_data = cognito_client
        .admin_get_user()
        .user_pool_id(&user_pool_id)
        .username(username)
        .send()
        .await?;

    let mut store_keys: Vec<String> = Vec::with_capacity(10);

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

    let mut key_manager = init_key_manager(None, None);
    let store_id = match key_manager.validate_store_id(&request.store_id) {
        Ok(v) => v,
        Err(_) => return error_resp(400, "Store ID could not be verified")
    };

    store_keys.push(store_id.encoded_id);
    let updated_value = serde_json::to_string(&store_keys).unwrap_or("[]".to_string());

    cognito_client
        .admin_update_user_attributes()
        .user_pool_id(&user_pool_id)
        .username(username)
        .user_attributes(AttributeType::builder()
            .name("custom:store_keys")
            .value(updated_value)
            .build()?
        ).send()
        .await?; 

    let mut metrics_item = AttributeValueHashMap::new();
    let store_index = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT).to_vec();
    metrics_item.insert_item(&METRICS_TABLE.store_id, Blob::new(store_index));
    
    let keys_and_attributes = KeysAndAttributes::builder()
        .set_consistent_read(Some(false))
        .keys(metrics_item)
        .build()?;
    let mut request_items: HashMap<String, KeysAndAttributes> = HashMap::with_capacity(2);
    request_items.insert(METRICS_TABLE.table_name.to_string(), keys_and_attributes.clone());
    request_items.insert(STORES_TABLE.table_name.to_string(), keys_and_attributes);

    let batch_get_item_output = db_client
        .batch_get_item()
        .set_request_items(Some(request_items))
        .send()
        .await?;

    let metrics_result = if let Some(v) = &batch_get_item_output.responses.as_ref().and_then(|responses| responses.get(METRICS_TABLE.table_name).cloned()) {
        if v.is_empty() {
            StoreMetricsJSON::default()
        } else {
            let m = &v[0];
            StoreMetricsJSON {
                num_products: m.get_item(&METRICS_TABLE.num_products).unwrap_or(&"0".to_string()).parse::<u32>()?,
                num_licenses: m.get_item(&METRICS_TABLE.num_licenses).unwrap_or(&"0".to_string()).parse::<u32>()?,
                num_licensed_machines: m.get_item(&METRICS_TABLE.num_licensed_machines).unwrap_or(&"0".to_string()).parse::<u32>()?,
                num_offline_machines: m.get_item(&METRICS_TABLE.num_offline_machines).unwrap_or(&"0".to_string()).parse::<u32>()?,
                num_online_machines: m.get_item(&METRICS_TABLE.num_online_machines).unwrap_or(&"0".to_string()).parse::<u32>()?,
                num_license_activations: m.get_item(&METRICS_TABLE.num_license_activations).unwrap_or(&"0".to_string()).parse::<u32>()?,
                num_license_regens: m.get_item(&METRICS_TABLE.num_license_regens).unwrap_or(&"0".to_string()).parse::<u32>()?,
                num_machine_deactivations: m.get_item(&METRICS_TABLE.num_machine_deactivations).unwrap_or(&"0".to_string()).parse::<u32>()?,
            }
        }
    } else {
        StoreMetricsJSON::default()
    };

    let configs = if let Some(v) = batch_get_item_output.responses.and_then(|responses| responses.get(STORES_TABLE.table_name).cloned()) {
        if v.is_empty() {
            Configs::default()
        } else {
            let store_item = &v[0];
            let encrypted_proto = store_item.get_item(&STORES_TABLE.protobuf_data)?;
            let proto: StoreDbItem = key_manager.decrypt_db_proto(&STORES_TABLE.table_name, store_id.binary_id.as_ref(), encrypted_proto.as_ref())?;
            if proto.configs.is_none() {
                return error_resp(500, "Could not decrypt StoreDbItem");
            }
            let c = proto.configs.unwrap();
            Configs {
                offline_license_frequency_hours: c.offline_license_frequency_hours,
                perpetual_license_expiration_days: c.perpetual_license_expiration_days,
                perpetual_license_frequency_hours: c.perpetual_license_frequency_hours,
                subscription_license_expiration_days: c.subscription_license_expiration_days,
                subscription_license_expiration_leniency_hours: c.subscription_license_expiration_leniency_hours,
                subscription_license_frequency_hours: c.subscription_license_frequency_hours,
                trial_license_expiration_days: c.trial_license_expiration_days,
                trial_license_frequency_hours: c.trial_license_frequency_hours,
            }
        }
    } else {
        Configs::default()
    };

    let response = LinkStoreResponse {
        metrics: metrics_result,
        configs,
    };
    let resp = serde_json::to_string(&response).expect("Failed to serialize JSON response");

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
