use std::{collections::HashMap, env};

use utils::{
    aws_config, aws_sdk_cognitoidentityprovider::Client as CognitoClient, aws_sdk_dynamodb::{types::KeysAndAttributes, Client as DbClient}, crypto::{init_key_manager, salty_hash, DigitalLicensingThemedKeymanager, STORE_DB_SALT}, prelude::{
        lambda_http::{
            run, 
            service_fn, 
            tracing, 
            Body, 
            Error, 
            Request, 
            RequestExt, 
            Response
        }, proto::protos::get_metrics_request::{GetMetricsResponse, Metrics}, AttributeValueHashMap, Blob, ItemIntegration, Message
    }, serde_json, tables::metrics::METRICS_TABLE
};

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
            if attr.name() == "custom::store_keys" {
                if let Some(value) = attr.value {
                    if let Ok(parsed) = serde_json::from_str::<Vec<String>>(&value) {
                        store_keys = parsed;
                    }
                }
            }
        }
    }

    if store_keys.is_empty() {
        return error_resp(400, "No stores found.");
    }

    let mut key_manager = init_key_manager(None, None);

    let mut id_to_store_indices: HashMap<Vec<u8>, String> = HashMap::with_capacity(10);
    let mut metrics_result: HashMap<String, Metrics> = HashMap::with_capacity(10);
    let mut keys_and_attributes: Vec<AttributeValueHashMap> = Vec::with_capacity(10);
    let mut totals = Metrics {
        num_products: 0,
        num_licenses: 0,
        num_licensed_machines: 0,
        num_offline_machines: 0,
        num_online_machines: 0,
        num_license_activations: 0,
        num_license_regens: 0,
        num_machine_deactivations: 0,
    };

    for key in store_keys.iter() {
        let id = match key_manager.validate_store_id(&key) {
            Ok(v) => v,
            Err(_) => return error_resp(500, "Error 3790")
        };
        let mut store_item = AttributeValueHashMap::with_capacity(1);
        let store_index = salty_hash(&[id.binary_id.as_ref()], &STORE_DB_SALT).to_vec();
        store_item.insert_item(&METRICS_TABLE.store_id, Blob::new(store_index.clone()));
        keys_and_attributes.push(store_item);
        id_to_store_indices.insert(store_index, key.to_owned());
        // insert default Metrics data for all indices in case there are any 
        // missing from the `batch_get_output`
        metrics_result.insert(key.to_owned(), Metrics {
            num_products: 0,
            num_licenses: 0,
            num_licensed_machines: 0,
            num_offline_machines: 0,
            num_online_machines: 0,
            num_license_activations: 0,
            num_license_regens: 0,
            num_machine_deactivations: 0,
        });
    }

    let k = KeysAndAttributes::builder()
        .consistent_read(false)
        .set_keys(Some(keys_and_attributes))
        .build()?;

    let mut items: HashMap<String, KeysAndAttributes> = HashMap::with_capacity(1);
    items.insert(METRICS_TABLE.table_name.to_string(), k);

    let batch_get_output = db_client
        .batch_get_item()
        .set_request_items(Some(items))
        .send()
        .await?;

    let metrics_responses = batch_get_output
        .responses
        .and_then(|responses| responses.get(METRICS_TABLE.table_name).cloned())
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
        metrics_result.insert(api_key, Metrics {
            num_products,
            num_licenses,
            num_licensed_machines,
            num_offline_machines,
            num_online_machines,
            num_license_activations,
            num_license_regens,
            num_machine_deactivations,
        });

        totals.num_license_activations += num_license_activations;
        totals.num_license_regens += num_license_regens;
        totals.num_licensed_machines += num_licensed_machines;
        totals.num_licenses += num_licenses;
        totals.num_machine_deactivations += num_machine_deactivations;
        totals.num_offline_machines += num_offline_machines;
        totals.num_online_machines += num_online_machines;
        totals.num_products += num_products;
    }
        
    let response = GetMetricsResponse {
        store_metrics: metrics_result,
        totals: Some(totals),
    };


    let resp = response.encode_to_vec();

    Ok(Response::builder()
        .status(200)
        .header("Content-type", "application/x-protobuf")
        .body(Body::Binary(resp))
        .unwrap())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}
