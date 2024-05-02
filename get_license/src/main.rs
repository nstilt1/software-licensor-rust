//mod my_crypt;
mod my_modules;
use my_modules::networking::output::license::License;
use my_modules::networking::output::response::HttpResponse;
use my_modules::crypto::aes::*;
use my_modules::crypto::rsa::{Crypto, verify_signature};
use my_modules::crypto::private::encrypt_id;

use lambda_http::{run, service_fn, Body, Error, Request, RequestExt, Response};

extern crate openssl;
use serde_derive::Serialize;
use substring::Substring;
use std::collections::HashMap;
use serde::Deserialize;
//use serde::{Deserialize, Serialize};

use rusoto_core::Region;
use rusoto_dynamodb::{
    AttributeValue,
    DynamoDb, 
    DynamoDbClient, 
    GetItemInput,
};

use std::time::{SystemTime, UNIX_EPOCH};



//static LICENSE_TABLE_NAME: &str = "Licenses";
//static PLUGINS_TABLE_NAME: &str = "Plugins";
static COMPANY_TABLE_NAME: &str = "Companies";
//static ORDERS_TABLE_NAME: &str = "Orders";
static USERS_TABLE_NAME: &str = "PluginUsers";

#[derive(Deserialize, Debug)]
struct MyRequest {
    data: String,
    nonce: String,
    key: String,
    timestamp: String,
    signature: String
}

#[derive(Serialize, Deserialize, Debug)]
struct Data {
    store_id: String,
    uuid: String,
}

pub fn cleanse (text: &str, extra_chars: &str, to_upper: bool) -> String {
    let mut allowed_chars = "ASDFGHJKLQWERTYUIOPZXCVBNM1234567890".to_owned();
    allowed_chars.push_str(extra_chars);
    let mut output = "".to_owned();
    for ch in text.chars() {
        let upper = ch.to_ascii_uppercase();
        if allowed_chars.contains(upper){
            output.push(if to_upper {upper} else {ch});
        }
    }
    output.to_owned()
}

fn error_resp(code: u16, message: &str) -> Result<Response<Body>, Error> {
    return Ok(Response::builder()
        .status(code)
        .header("content-type", "text/html")
        .body(message.into())
        .map_err(Box::new)?);
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
                return error_resp(400, &format!("Error with request parameters: {:?}", 
                    rq_check.unwrap_err().to_string()));
            }

            let rq = rq_check.unwrap();
            
            //let data = &rq.data;
            let nonce = &rq.nonce;
            let encrypted_key = &rq.key;
            let timestamp = &rq.timestamp;
            let signature = &rq.signature;

            
            let signed_stuff = format!("{}{}{}{}", &rq.data, &nonce, &encrypted_key, &timestamp);

            let current_time = SystemTime::duration_since (&SystemTime::now(), UNIX_EPOCH).unwrap().as_secs();
            if timestamp.parse::<u64>().unwrap() < current_time - 60 {
                return error_resp(400,"Timestamp too old. Needs to be in seconds.");
            }
            let decrypted_key_result = encrypted_key.to_owned().rsa_decrypt();
            if decrypted_key_result.as_ref().is_err() {
                return decrypted_key_result.unwrap_err().respond();
            }

            let decrypted_data_result = rq.data.aes_decrypt(decrypted_key_result.unwrap(), &nonce);
            if decrypted_data_result.as_ref().is_err() {
                return decrypted_data_result.unwrap_err().respond();
            }

            let aes_data_result: Result<Data, serde_json::Error> = serde_json::from_str(&decrypted_data_result.unwrap());
            if aes_data_result.is_err() {
                return error_resp(500, &format!("Error CC63: {:?}", aes_data_result.unwrap_err()));
            }

            let rq = aes_data_result.unwrap();

            let company = cleanse(&rq.store_id, "", true);
            let uuid = &rq.uuid;

            //let signed_stuff = format!("{}{}{}", &company, &uuid, &timestamp);
            /*
            let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            if timestamp.parse::<u64>().unwrap() < current_time - 300 {
                return error_resp(400, "Timestamp invalid");
            }
            */

            let mut company_key_map: HashMap<String, AttributeValue> = HashMap::new();
            company_key_map.insert(
                "id".to_owned(),
                AttributeValue {
                    s: Some(encrypt_id(&company, true, false)),
                    ..Default::default()
                }
            );
            let get_company = client.get_item(
                GetItemInput {
                    table_name: COMPANY_TABLE_NAME.to_owned(),
                    key: company_key_map.to_owned(),
                    consistent_read: Some(true),
                    ..Default::default()
                }
            ).await;

            if get_company.is_err() {
                return error_resp(500, &format!("Error GL305w: {:?}", &get_company.unwrap_err().to_string()));
            }

            let get_comp_out = get_company.as_ref().unwrap().item.as_ref();
            if get_comp_out.is_none() {
                return error_resp(400, "Company not found");
            }

            let get_comp_item = get_comp_out.unwrap();
            let public_key_option = get_comp_item.get("publicKeyA");
            if public_key_option.is_none() {
                return error_resp(500, "Error GL316j. Contact Plugin Licensor");
            }
            //let public_pkey = PKey::public_key_from_pem(&public_key_option.unwrap().s.as_ref().unwrap().to_owned().as_bytes()).unwrap();
            
            let key_is_valid = verify_signature(&public_key_option.unwrap().s.as_ref().unwrap(), &signed_stuff, &signature);
            if key_is_valid.is_err() {
                return error_resp(400, &format!("Error with your public key: {:?}", key_is_valid.unwrap_err()));
            }

            // signature is valid 

            let mut order_key_map: HashMap<String, AttributeValue> = HashMap::new();
            order_key_map.insert(
                "company".to_owned(),
                AttributeValue {
                    s: Some(company.to_owned()),
                    ..Default::default()
                }
            );
            order_key_map.insert(
                "uuid".to_owned(),
                AttributeValue {
                    s: Some(uuid.to_owned()),
                    ..Default::default()
                }
            );

            let get_user_result = client.get_item(
                GetItemInput {
                    table_name: USERS_TABLE_NAME.to_owned(),
                    key: order_key_map.to_owned(),
                    consistent_read: Some(true),
                    ..Default::default()
                }
            ).await;

            if get_user_result.is_err() {
                return error_resp(500, &format!("Error GL354w: {:?}", get_user_result.unwrap_err()));
            }
            let get_user_option = get_user_result.unwrap().item;
            if get_user_option.is_none() {
                return error_resp(400, "Order not found");
            }
            let get_user_item = get_user_option.unwrap();
            let license_index_opt = get_user_item.get("licenseIndex");
            if license_index_opt.is_none() {
                return error_resp(500, "Error GL363p: Contact Plugin Licensor");
            }
            let license_index = license_index_opt.unwrap().s.as_ref().unwrap().to_owned();

            let offline_code_opt = get_user_item.get("OfflineSecret");
            if offline_code_opt.is_none() {
                return error_resp(500, "Error GL188d");
            }
            //let offline_code = offline_code_opt.unwrap().s.as_ref().unwrap().to_owned();
            
            let decrypted_license_index = encrypt_id(&license_index, false, true).to_owned();
            let license_code = decrypted_license_index.substring(decrypted_license_index.len()-20, decrypted_license_index.len());
            
            let licenses_opt = get_user_item.get("licenses");
            if licenses_opt.is_none() {
                return error_resp(500, "Error GL173j");
            }
            
            let licenses_obj = licenses_opt.unwrap().m.as_ref().unwrap().to_owned();

            // extract license and machine data to go into the licenses_output
            //let mut licenses_output: License = License::new(&license_code);
            let licenses_result = License::init_license(&license_code, licenses_obj);

            if licenses_result.is_err() {
                return licenses_result.unwrap_err().respond()
            }
            let license_output = licenses_result.unwrap();

            let json_license_result = serde_json::to_string(&license_output);
            if json_license_result.is_err() {
                return error_resp(500, &format!("Error GL191q: {:?}", json_license_result.unwrap_err()));
            }

            let json_license_str = json_license_result.unwrap();

            // encrypt `json_license_str` with AES key
            let encrypt_result = json_license_str.aes_encrypt();
            if encrypt_result.as_ref().is_err() {
                return encrypt_result.unwrap_err().respond();
            }
            let encrypt_tuple = encrypt_result.as_ref().unwrap().to_owned();
            
            let out = HttpResponse::new(
                encrypt_tuple, public_key_option.unwrap().s.as_ref().unwrap().as_str() 
            );
            if out.as_ref().is_err() {
                return out.unwrap_err().respond();
            }
            let out_json = serde_json::to_string(&out.unwrap()).unwrap();



            //let encrypted_license_code = format!("{:?}", buf);
            let resp = Response::builder()
                .status(200)
                .header("content-type", "text/html")
                .body(out_json.into())
                .map_err(Box::new)?;
            Ok(resp)
        }, 
        _ => {
            return error_resp(400, "Payload mismatch");
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
