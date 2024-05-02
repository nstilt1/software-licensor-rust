use lambda_http::{run, service_fn, Body, Error, Request, RequestExt, Response};

mod my_modules;
use my_modules::crypto::aes::*;
use my_modules::crypto::rsa::Crypto;
use my_modules::db::*;
use my_modules::utils::utils::*;
use my_modules::crypto::rsa::*;

use serde_json::Value;
use serde::Deserialize;

use rusoto_core::Region;
use rusoto_dynamodb::DynamoDbClient;

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Deserialize, Debug)]
struct MyRequest {
    data: String,
    nonce: String,
    key: String,
    timestamp: String,
    signature: String,
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
async fn function_handler(event: Request) -> Result<Response<Body>, Error> {

    let params = event.query_string_parameters().to_query_string();
    if params.len() > 0 {
        return error_resp(400, "Invalid request. Query Strings shall not pass!");
    }
    let payload = event.body();

    match payload {
        Body::Text(contents) => {
            let client: DynamoDbClient = DynamoDbClient::new(Region::UsEast1);

            let rq_check: Result<MyRequest, serde_json::Error> = serde_json::from_str(contents);
            if rq_check.is_err() {
                return error_resp(400, &format!("Error CC1: error with request parameters: {:?}\ncontents: {}", rq_check.unwrap_err().to_string(), contents));
            }
            let rq = rq_check.unwrap();

            let data = &rq.data;
            let nonce = &rq.nonce;
            let encrypted_key = &rq.key;
            let timestamp = &rq.timestamp;
            let signature = &rq.signature;

            
            let signed_stuff = format!("{}{}{}{}", &data, &nonce, &encrypted_key, &timestamp);

            let current_time = SystemTime::duration_since(&SystemTime::now(), UNIX_EPOCH).unwrap().as_secs();
            let time_since = current_time - timestamp.parse::<u64>().unwrap();
            if time_since > 60 {
                return error_resp(400,&format!("Timestamp too old. Report this to Plugin Licensor. {}", time_since.to_string()));
            } 

            let decrypted_key_result = encrypted_key.rsa_decrypt();
            if decrypted_key_result.as_ref().is_err() {
                return decrypted_key_result.unwrap_err().respond();
            }

            let decrypted_data_result = data.aes_decrypt(decrypted_key_result.unwrap(), &nonce);
            if decrypted_data_result.as_ref().is_err() {
                return decrypted_data_result.unwrap_err().respond();
            }

            let aes_data_result = serde_json::from_str(&decrypted_data_result.unwrap());
            if aes_data_result.is_err() {
                return error_resp(500, &format!("Error CC63: {:?}", aes_data_result.unwrap_err()));
            }
            let aes_data:Value = aes_data_result.unwrap();

            // extract store info from aes_data:
            // public key to save in DB
            let store_pub_key_opt: Option<&str> = aes_data["key"].as_str();
            if store_pub_key_opt.is_none() {
                return error_resp(400, "Error CC72: Missing 'key' in 'data'");
            }
            let store_pub_key = store_pub_key_opt.unwrap();
            let key_is_valid = verify_signature(&store_pub_key, &signed_stuff, &signature);
            if key_is_valid.is_err() {
                return error_resp(400, &format!("Error with your public key: {:?}", key_is_valid.unwrap_err()));
            }

            // customer name
            let customer_first_name_opt: Option<&str> = aes_data["first_name"].as_str();
            if customer_first_name_opt.is_none() {
                return error_resp(400, "Missing first name.");
            }
            let customer_first_name = customer_first_name_opt.unwrap();

            let customer_last_name_opt: Option<&str> = aes_data["last_name"].as_str();
            if customer_last_name_opt.is_none() {
                return error_resp(400, "Missing last name.");
            }
            let customer_last_name = customer_last_name_opt.unwrap();

            // customer discord id
            let customer_discord_opt: Option<&str> = aes_data["discord"].as_str();
            if customer_discord_opt.is_none() {
                return error_resp(400, "Missing discord id.");
            }
            let customer_discord = customer_discord_opt.unwrap();

            


            // store name to convert into store ID
            let store_name_opt: Option<&str> = aes_data["store_id_prefix"].as_str();
            if store_name_opt.is_none() {
                return error_resp(400, "Error CC73: Missing 'store_id_prefix' in 'data'.");
            }
            let store_name = store_name_opt.unwrap();
            let store_id_result = generate_store_id(client.to_owned(), &store_name).await;
            if store_id_result.is_err() {
                return error_resp(500, &format!("Error CC78: {:?}", store_id_result.unwrap_err()));
            }

            let store_output = store_id_result.unwrap();
            let store_id_string = store_output.0;
            let store_id_map = store_output.1;

            // create the company in the table
            let create_comp_result = create_company_item(
                client.to_owned(), 
                current_time, 
                store_name, 
                store_id_map, 
                store_pub_key, 
                customer_first_name, 
                customer_last_name, 
                customer_discord).await;
            
            if create_comp_result.is_err() {
                return error_resp(500, &create_comp_result.unwrap_err());
            }
            
            
            
            // This is being done manually to prevent an error from unwrapping the serde_json creation. It is a simple enough line of code here to do this
            // also because I didn't have some structs and methods developed
            return success_response(&format!(r#"{{"store_id": "{}"}}"#, &store_id_string), store_pub_key);
            
            

            //return error_resp(500, "Unimplemented");
            /*
            // Return something that implements IntoResponse.
            // It will be serialized to the right response event automatically by the runtime
            let resp = Response::builder()
            .status(200)
            .header("content-type", "text/html")
            .body(message.into())
            .map_err(Box::new)?;
            Ok(resp)
            */
        },
        _ => {
            return error_resp(400, "Invalid request body.");
        }
    
}
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    run(service_fn(function_handler)).await
}
