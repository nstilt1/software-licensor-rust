use std::{collections::HashMap, env};

use utils::{aws_config, aws_sdk_cognitoidentityprovider::types::AttributeType, aws_sdk_dynamodb::Client, crypto::{init_key_manager, salty_hash, DigitalLicensingThemedKeymanager, STORE_DB_SALT}, debug_log, now_as_seconds, prelude::{lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response}, proto::protos::create_store_request::{Configs as StoreConfigs, StoreDbItem}, AttributeValueHashMap, Blob, ItemIntegration}, tables::stores::STORES_TABLE};
use utils::aws_sdk_cognitoidentityprovider::Client as CognitoClient;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct CreateStoreRequest {
    id_prefix: String,
    contact_first_name: String,
    contact_last_name: String,
    contact_email: String,
    discord_username: String,
    country: String,
    store_name: String,
    store_url: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CreateStoreResponse {
    api_key: String,
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

fn error_resp(status: u16, contents: &str) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(status)
        .body(Body::Text(contents.to_string()))
        .unwrap())
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

    let request: CreateStoreRequest = match serde_json::from_str(&body) {
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

    if store_keys.len() >= 10 {
        return error_resp(400, "You have reached the maximum amount of stores.");
    }

    // init key manager and generate an API key and item
    let mut key_manager = init_key_manager(None, None);
    let mut store_id = key_manager.generate_store_id(&request.id_prefix)?;
    let db_client = Client::new(&config);
    let mut store_item = AttributeValueHashMap::with_capacity(1);
    loop {
        let hashed_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);

        store_item.insert_item(&STORES_TABLE.id, Blob::new(hashed_id.to_vec()));

        let get_output = db_client.get_item()
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

    let configs = Configs {
        offline_license_frequency_hours: 1000,
        perpetual_license_expiration_days: 720,
        perpetual_license_frequency_hours: 600,
        subscription_license_expiration_days: 30,
        subscription_license_expiration_leniency_hours: 24,
        subscription_license_frequency_hours: 72,
        trial_license_expiration_days: 7,
        trial_license_frequency_hours: 120,
    };

    let proto = StoreDbItem {
        contact_first_name: request.contact_first_name,
        contact_last_name: request.contact_last_name,
        store_name: request.store_name,
        email: request.contact_email,
        store_url: request.store_url,
        discord_username: request.discord_username,
        country: request.country,
        configs: Some(StoreConfigs {
            offline_license_frequency_hours: configs.offline_license_frequency_hours,
            perpetual_license_expiration_days: configs.perpetual_license_expiration_days,
            perpetual_license_frequency_hours: configs.perpetual_license_frequency_hours,
            subscription_license_expiration_days: configs.subscription_license_expiration_days,
            subscription_license_expiration_leniency_hours: configs.subscription_license_expiration_leniency_hours,
            subscription_license_frequency_hours: configs.subscription_license_frequency_hours,
            trial_license_expiration_days: configs.trial_license_expiration_days,
            trial_license_frequency_hours: configs.trial_license_frequency_hours,
        }),
        product_ids: HashMap::new(),
        state: "".to_string()
    };

    let encrypted_protobuf = key_manager.encrypt_db_proto(&STORES_TABLE.table_name, store_id.binary_id.as_ref(), &proto)?;

    debug_log!("Encrypted store db item");

    store_item.insert_item(&STORES_TABLE.protobuf_data, Blob::new(encrypted_protobuf));

    store_item.insert_item(&STORES_TABLE.public_key, Blob::new(&[]));
    store_item.insert_item(&STORES_TABLE.registration_date, now_as_seconds().to_string());

    db_client.put_item()
        .table_name(STORES_TABLE.table_name)
        .set_item(Some(store_item))
        .send()
        .await?;

    debug_log!("Put store item in database");

    // add new API key to attributes
    store_keys.push(store_id.encoded_id.clone());

    let updated_value = serde_json::to_string(&store_keys).unwrap_or("[]".to_string());

    let cognito_request = cognito_client
        .admin_update_user_attributes()
        .user_pool_id(&user_pool_id)
        .username(username)
        .user_attributes(AttributeType::builder()
            .name("custom:store_keys")
            .value(updated_value)
            .build()?
        ).send()
        .await?;

    debug_log!("Cognito request: {:?}", cognito_request);

    let response_message = CreateStoreResponse {
        api_key: store_id.encoded_id,
        configs,
    };

    let resp = serde_json::to_string(&response_message).expect("Failed to serialize JSON response");

    Ok(Response::builder()
        .status(200)
        .header("Content-type", "application/x-protobuf")
        .body(Body::Text(resp))
        .unwrap())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}
