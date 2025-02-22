use std::{collections::HashMap, env};

use utils::{
    aws_config, aws_sdk_cognitoidentityprovider::Client as CognitoClient, aws_sdk_dynamodb::{types::KeysAndAttributes, Client as DbClient}, crypto::{init_key_manager, salty_hash, DigitalLicensingThemedKeymanager, STORE_DB_SALT}, debug_log, prelude::{
        lambda_http::{
            run, 
            service_fn, 
            tracing, 
            Body, 
            Error, 
            Request, 
            RequestExt, 
            Response
        }, proto::protos::create_store_request::StoreDbItem, AttributeValueHashMap, Blob, ItemIntegration
    }, serde_json, tables::{metrics::METRICS_TABLE, stores::STORES_TABLE}
};

use serde::{Deserialize, Serialize};

fn error_resp(status: u16, contents: &str) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(status)
        .body(Body::Text(contents.to_string()))
        .unwrap())
}

#[derive(Serialize, Deserialize, Debug)]
struct GetMetricsRequest {

}

#[derive(Serialize, Deserialize, Debug)]
struct GetMetricsResponse {
    store_data: HashMap<String, StoreData>,
    totals: StoreMetricsJSON
}

#[derive(Serialize, Deserialize, Debug)]
struct StoreData {
    api_key: String,
    configs: Configs,
    metrics: StoreMetricsJSON
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
        return error_resp(401, "Unauthorized: Missing sub claim")
    }

    let config = aws_config::load_from_env().await;
    let cognito_client = CognitoClient::new(&config);
    let db_client = DbClient::new(&config);

    let user_pool_id = env::var("USER_POOL_ID").expect("USER_POOL_ID not set");
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

    if store_keys.is_empty() {
        debug_log!("store_keys.is_empty()");
        let response = GetMetricsResponse {
            store_data: HashMap::new(),
            totals: StoreMetricsJSON::default(),
        };

        let resp = serde_json::to_string(&response).expect("Failed to serialize JSON response");
        return Ok(Response::builder()
            .status(200)
            .header("Content-type", "application/json")
            .body(Body::Text(resp))
            .unwrap())
    }

    let mut key_manager = init_key_manager(None, None);

    let mut id_to_store_indices: HashMap<Vec<u8>, String> = HashMap::with_capacity(10);
    let mut result: HashMap<String, StoreData> = HashMap::with_capacity(10);
    let mut keys_and_attributes: Vec<AttributeValueHashMap> = Vec::with_capacity(10);
    let mut totals = StoreMetricsJSON::default();

    for key in store_keys.iter() {
        let id = match key_manager.validate_store_id(&key) {
            Ok(v) => v,
            Err(_) => {
                debug_log!("Error validating store ID. ID = {:?}", key);
                return error_resp(500, "Error 3790")
            }
        };
        let mut store_item = AttributeValueHashMap::with_capacity(1);
        let store_index = salty_hash(&[id.binary_id.as_ref()], &STORE_DB_SALT).to_vec();
        store_item.insert_item(&METRICS_TABLE.store_id, Blob::new(store_index.clone()));
        keys_and_attributes.push(store_item);
        id_to_store_indices.insert(store_index, key.to_owned());
        // insert default Metrics data for all indices in case there are any 
        // missing from the `batch_get_output`
        result.insert(key.to_owned(), 
            StoreData {
                api_key: key.to_owned(),
                configs: Configs::default(),
                metrics: StoreMetricsJSON::default(),
            }
        );
    }

    let k = KeysAndAttributes::builder()
        .consistent_read(false)
        .set_keys(Some(keys_and_attributes))
        .build()?;

    let mut items: HashMap<String, KeysAndAttributes> = HashMap::with_capacity(2);
    items.insert(METRICS_TABLE.table_name.to_string(), k.clone());
    items.insert(STORES_TABLE.table_name.to_string(), k);

    let batch_get_output = db_client
        .batch_get_item()
        .set_request_items(Some(items))
        .send()
        .await?;

    let metrics_responses = batch_get_output
        .responses.clone()
        .and_then(|responses| responses.get(METRICS_TABLE.table_name).cloned())
        .unwrap_or(Vec::new());

    let stores_responses = batch_get_output
        .responses
        .and_then(|responses| responses.get(STORES_TABLE.table_name).cloned())
        .unwrap_or(Vec::new());

    for item in metrics_responses {
        let id = item.get_item(&METRICS_TABLE.store_id)?;
        let api_key = match id_to_store_indices.get(id.as_ref()) {
            Some(v) => v.to_owned(),
            None => String::new()
        };
        let num_products = item.get_item(&METRICS_TABLE.num_products).unwrap_or(&"0".to_string()).parse::<u32>()?;
        let num_licenses = item.get_item(&METRICS_TABLE.num_licenses).unwrap_or(&"0".to_string()).parse::<u32>()?;
        let num_licensed_machines = item.get_item(&METRICS_TABLE.num_licensed_machines).unwrap_or(&"0".to_string()).parse::<u32>()?;
        let num_offline_machines = item.get_item(&METRICS_TABLE.num_offline_machines).unwrap_or(&"0".to_string()).parse::<u32>()?;
        let num_online_machines = item.get_item(&METRICS_TABLE.num_online_machines).unwrap_or(&"0".to_string()).parse::<u32>()?;
        let num_license_activations = item.get_item(&METRICS_TABLE.num_license_activations).unwrap_or(&"0".to_string()).parse::<u32>()?;
        let num_license_regens = item.get_item(&METRICS_TABLE.num_license_regens).unwrap_or(&"0".to_string()).parse::<u32>()?;
        let num_machine_deactivations = item.get_item(&METRICS_TABLE.num_machine_deactivations).unwrap_or(&"0".to_string()).parse::<u32>()?;
        
        let i = result.get_mut(&api_key).expect("Should exist");
        
        i.metrics = StoreMetricsJSON {
            num_products,
            num_licenses,
            num_licensed_machines,
            num_offline_machines,
            num_online_machines,
            num_license_activations,
            num_license_regens,
            num_machine_deactivations,
        };

        totals.num_license_activations += num_license_activations;
        totals.num_license_regens += num_license_regens;
        totals.num_licensed_machines += num_licensed_machines;
        totals.num_licenses += num_licenses;
        totals.num_machine_deactivations += num_machine_deactivations;
        totals.num_offline_machines += num_offline_machines;
        totals.num_online_machines += num_online_machines;
        totals.num_products += num_products;
    }

    for item in stores_responses {
        let id = item.get_item(&STORES_TABLE.id)?;
        let api_key = match id_to_store_indices.get(id.as_ref()) {
            Some(v) => v.to_owned(),
            None => String::new()
        };

        let store_id = key_manager.validate_store_id(&api_key)?;

        let encrypted_proto = item.get_item(&STORES_TABLE.protobuf_data)?;
        let proto: StoreDbItem = key_manager.decrypt_db_proto(&STORES_TABLE.table_name, store_id.binary_id.as_ref(), &encrypted_proto.as_ref())?;
        if let Some(v) = proto.configs {
            let i = result.get_mut(&api_key).expect("Should be set");
            i.configs = Configs {
                offline_license_frequency_hours: v.offline_license_frequency_hours,
                perpetual_license_expiration_days: v.perpetual_license_expiration_days,
                perpetual_license_frequency_hours: v.perpetual_license_frequency_hours,
                subscription_license_expiration_days: v.subscription_license_expiration_days,
                subscription_license_expiration_leniency_hours: v.subscription_license_expiration_leniency_hours,
                subscription_license_frequency_hours: v.subscription_license_frequency_hours,
                trial_license_expiration_days: v.trial_license_expiration_days,
                trial_license_frequency_hours: v.trial_license_frequency_hours,
            };
        }
    }
        
    let response = GetMetricsResponse {
        totals,
        store_data: result,
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
