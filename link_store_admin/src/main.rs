use utils::{
    aws_config, aws_sdk_cognitoidentityprovider::{types::AttributeType, Client as CognitoClient}, aws_sdk_dynamodb::Client as DbClient, crypto::{init_key_manager, salty_hash, DigitalLicensingThemedKeymanager, STORE_DB_SALT}, prelude::{
        lambda_http::{
            run, service_fn, tracing, Body, Error, Request, RequestExt, Response
        }, proto::protos::{get_metrics_request::Metrics, link_store_request::LinkStoreRequest}, AttributeValueHashMap, Blob, ItemIntegration, Message
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
        return error_resp(401, "Unauthorized: Missing sub claim");
    }

    let body = match event.body() {
        Body::Binary(b) => b,
        _ => return error_resp(400, "Invalid request body")
    };

    let request = match LinkStoreRequest::decode(body.as_slice()) {
        Ok(v) => v,
        Err(_e) => return error_resp(400, "Invalid protobuf request body")
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
    
    let get_output = db_client
        .get_item()
        .table_name(METRICS_TABLE.table_name)
        .set_key(Some(metrics_item))
        .set_consistent_read(Some(false))
        .send()
        .await?;

    let metrics_result = if get_output.item.is_none() {
        Metrics {
            num_products: 0,
            num_licenses: 0,
            num_licensed_machines: 0,
            num_offline_machines: 0,
            num_online_machines: 0,
            num_license_activations: 0,
            num_license_regens: 0,
            num_machine_deactivations: 0,
        }
    } else {
        let m = get_output.item.unwrap();
        Metrics {
            num_products: m.get_item(&METRICS_TABLE.num_products).unwrap_or(&"0".to_string()).parse::<u32>()?,
            num_licenses: m.get_item(&METRICS_TABLE.num_licenses).unwrap_or(&"0".to_string()).parse::<u32>()?,
            num_licensed_machines: m.get_item(&METRICS_TABLE.num_licensed_machines).unwrap_or(&"0".to_string()).parse::<u32>()?,
            num_offline_machines: m.get_item(&METRICS_TABLE.num_offline_machines).unwrap_or(&"0".to_string()).parse::<u32>()?,
            num_online_machines: m.get_item(&METRICS_TABLE.num_online_machines).unwrap_or(&"0".to_string()).parse::<u32>()?,
            num_license_activations: m.get_item(&METRICS_TABLE.num_license_activations).unwrap_or(&"0".to_string()).parse::<u32>()?,
            num_license_regens: m.get_item(&METRICS_TABLE.num_license_regens).unwrap_or(&"0".to_string()).parse::<u32>()?,
            num_machine_deactivations: m.get_item(&METRICS_TABLE.num_machine_deactivations).unwrap_or(&"0".to_string()).parse::<u32>()?,
        }
    };

    let resp = metrics_result.encode_to_vec();

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
