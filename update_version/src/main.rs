use utils::{aws_config, crypto::{init_key_manager, salty_hash, DigitalLicensingThemedKeymanager, STORE_DB_SALT}, prelude::{lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response}, proto::protos::create_store_request::StoreDbItem, AttributeValueHashMap, Blob, ItemIntegration}, tables::stores::STORES_TABLE};
use serde::{Deserialize, Serialize};
use utils::aws_sdk_cognitoidentityprovider::Client as CognitoClient;
use utils::aws_sdk_dynamodb::Client as DbClient;

#[derive(Serialize, Deserialize, Debug)]
struct UpdateVersionRequest {
    store_id: String,
    product_id: String,
    new_version: String
}

#[derive(Serialize, Deserialize, Debug)]
struct UpdateVersionResponse {
    version: String
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
        return error_resp(401, "Unauthorized: Missing sub claim");
    }

    let body = match event.body() {
        Body::Text(b) => b,
        _ => return error_resp(400, "Invalid request body")
    };

    let request: UpdateVersionRequest = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return error_resp(400, &format!("Invalid request body: {}", e))
    };

    let config = aws_config::load_from_env().await;
    let cognito_client = CognitoClient::new(&config);

    let user_pool_id = std::env::var("USER_POOL_ID").expect("USER_POOL_ID not set");
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

    if store_keys.is_empty() {
        return error_resp(400, "No stores found");
    }
    if !store_keys.contains(&request.store_id) {
        return error_resp(404, "Store key not found");
    }

    let mut key_manager = init_key_manager(None, None);

    // fetch the store from the database
    let store_id = match key_manager.validate_store_id(&request.store_id) {
        Ok(v) => v,
        Err(_) => return error_resp(400, "Invalid store ID")
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
        return error_resp(404, "Store not found");
    }

    store_item = get_output.item.unwrap();

    // decrypt proto
    let encrypted_protobuf = store_item.get_item(&STORES_TABLE.protobuf_data)?;
    let mut proto: StoreDbItem = key_manager
        .decrypt_db_proto(
            &STORES_TABLE.table_name, 
            store_id.binary_id.as_ref(), 
            encrypted_protobuf.as_ref()
        )?;

    // check for presence of the product ID
    if !proto.product_ids.contains_key(&request.product_id) {
        return error_resp(404, "Product ID not found");
    }

    // update version
    proto.product_ids
        .get_mut(&request.product_id)
        .expect("We have already confirmed that the id exists")
        .version = request.new_version.to_string();

    // re-encrypt the proto
    let encrypted_protobuf = key_manager
        .encrypt_db_proto(
            &STORES_TABLE.table_name, 
            store_id.binary_id.as_ref(), 
            &proto
        )?;

    store_item.insert_item(&STORES_TABLE.protobuf_data, Blob::new(encrypted_protobuf));

    // update the DB
    db_client.put_item()
        .table_name(STORES_TABLE.table_name)
        .set_item(Some(store_item))
        .send()
        .await?;

    let response_message = UpdateVersionResponse {
        version: request.new_version.to_string()
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
