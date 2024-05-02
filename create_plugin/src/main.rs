use lambda_http::{run, service_fn, Body, Error, Request, RequestExt, Response};

mod my_modules;
use my_modules::crypto::aes::CryptoAES;
use my_modules::crypto::rsa::Crypto;
use my_modules::crypto::rsa::verify_signature;
use my_modules::db::*;
use my_modules::output::*;
use my_modules::license_request::*;

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
                return error_resp(400, &format!("Error with request parameters: {:?}", rq_check.unwrap_err().to_string()));
            }
            let rq = rq_check.unwrap();

            let data = &rq.data;
            let nonce = &rq.nonce;
            let encrypted_key = &rq.key;
            let timestamp = &rq.timestamp;
            let signature = &rq.signature;

            let signed_stuff = format!("{}{}{}{}", &data, &nonce, &encrypted_key, &timestamp);

            let current_time = SystemTime::duration_since(&SystemTime::now(), UNIX_EPOCH).unwrap().as_secs();
            if timestamp.parse::<u64>().unwrap() < current_time - 600 {
                return error_resp(400, "Timestamp invalid");
            } 

            let decrypted_key_result = encrypted_key.rsa_decrypt();
            if decrypted_key_result.as_ref().is_err() {
                return decrypted_key_result.unwrap_err().respond();
            }

            let decrypted_data_result = data.aes_decrypt(decrypted_key_result.unwrap(), &nonce);
            if decrypted_data_result.as_ref().is_err() {
                return decrypted_data_result.unwrap_err().respond();
            }

            let aes_data_result: Result<AesData, serde_json::Error> = serde_json::from_str(&decrypted_data_result.unwrap());
            if aes_data_result.is_err() {
                return error_resp(500, &format!("Error CP63: {:?}", aes_data_result.unwrap_err()));
            }
            let mut aes_data = aes_data_result.unwrap();

            let validation_result = aes_data.validate();
            if validation_result.is_err() {
                let validation_error = validation_result.unwrap_err();
                return error_resp(validation_error.0, &validation_error.1);
            }

            let juce_pub_opt = (&aes_data).juce_public_full.to_owned();
            // this should not be an error. If it is, there's something wrong with the way that juce_public_full is made
            // if it is an error, might need to make a method that returns the public key
            if juce_pub_opt.is_none() {
                return error_resp(500, "Error CPMF81");
            }

            let store_id = &aes_data.store_id;
            let plugin_name = &aes_data.plugin_id_prefix;


            // after getting the rest of the data,
            // get the data about the store from the db
            let company_item_result = get_company(client.to_owned(), store_id).await;
            if company_item_result.is_err() {
                let error_tuple = company_item_result.unwrap_err();
                return error_resp(error_tuple.0, &error_tuple.1);
            }
            let company_item = company_item_result.unwrap();

            // check if the signature is valid
            let pub_key_opt = company_item.get("publicKeyA");
            if pub_key_opt.is_none() {
                return error_resp(500, "Error CPM113: Error locating your public key.");
            }
            let pub_key_o = pub_key_opt.unwrap().s.as_ref();
            if pub_key_o.is_none() {
                return error_resp(500, "Error CPM117: Error locating your public key.");
            }
            let pub_key = pub_key_o.unwrap().to_owned();
            
            let signature_result = verify_signature(&pub_key, &signed_stuff, &signature);
            if signature_result.is_err() {
                return signature_result.unwrap_err().respond();
            }

            // signature is valid

            // generate plugin ID
            // use a batch write request to:
            // create a plugin
            // add plugin index to company's `plugins` map
            let partial_map = aes_data.get_hashmap();
            if partial_map.is_err() {
                return partial_map.unwrap_err().respond();
            }
// error below here
            let create_plugin_output_result = create_plugin(
                client.to_owned(), 
                &store_id,
                &plugin_name,
                company_item.to_owned(),
                partial_map.unwrap()
            ).await;
// error above here
            //return error_resp(500, "Made it to 134!");
            if create_plugin_output_result.is_err() {
                return create_plugin_output_result.unwrap_err().respond();
            }
            let plugin_id = create_plugin_output_result.unwrap();
            let license_types = aes_data.get_license_types();
            let languages = aes_data.get_languages();
// error above here

            // return:
                //plugin_id
                //license_types
                //accepted languages for responses
                //juce public key
            // in json format
            //return error_resp(500, "made it to 141");

            let json_out = AesOut::new(
                &plugin_id, 
                license_types, 
                languages,
                &juce_pub_opt.unwrap()
            ).to_json();

            if json_out.is_err() {
                return error_resp(500, &format!("Error CPM141: {}", json_out.unwrap_err()));
            }

            return success_response(&json_out.unwrap(), &pub_key);
        },
        _ => {
            return error_resp(400, "Error m77: invalid request.");
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
