use rusoto_dynamodb::{DynamoDbClient, DynamoDb, AttributeValue, GetItemInput, PutItemInput};
use substring::Substring;
use std::collections::HashMap;
use rand::prelude::*;

use crate::my_modules::crypto::custom::*;

use super::utils::utils::cleanse;

static COMPANY_TABLE_NAME: &str = "Companies";

/**
 * Create company item in Company table
 */
pub async fn create_company_item(
    client: DynamoDbClient, 
    current_time: u64,
    store_name: &str,
    store_map_in: HashMap<String, AttributeValue>,
    pub_key: &str,
    first_name: &str,
    last_name: &str,
    discord: &str) -> Result<(), String> {
    
    let mut store_map = store_map_in.clone();

    // insert store_name
    store_map.insert(
        "store_name".to_owned(),
        AttributeValue {
            s: Some(store_name.to_owned()),
            ..Default::default()
        }
    );

    // insert publicKeyA
    store_map.insert(
        "publicKeyA".to_owned(),
        AttributeValue {
            s: Some(pub_key.to_owned()),
            ..Default::default()
        }
    );

    // insert first_name
    store_map.insert(
        "first_name".to_owned(),
        AttributeValue {
            s: Some(first_name.to_owned()),
            ..Default::default()
        }
    );

    // insert last_name
    store_map.insert(
        "last_name".to_owned(),
        AttributeValue {
            s: Some(last_name.to_owned()),
            ..Default::default()
        }
    );

    // insert discord
    store_map.insert(
        "discord".to_owned(),
        AttributeValue {
            s: Some(discord.to_owned()),
            ..Default::default()
        }
    );

    // insert userId
    store_map.insert(
        "userId".to_owned(),
        AttributeValue {
            s: Some("Undefined".to_owned()),
            ..Default::default()
        }
    );

    // insert dateCreated
    store_map.insert(
        "dateCreated".to_owned(),
        AttributeValue {
            s: Some(current_time.to_string()),
            ..Default::default()
        }
    );

    // insert plugins list
    let empty_plugin_map: HashMap<String, AttributeValue> = HashMap::new();
    store_map.insert(
        "plugins".to_owned(),
        AttributeValue {
            m: Some(empty_plugin_map.to_owned()),
            ..Default::default()
        }
    );

    let put_input = PutItemInput {
        table_name: COMPANY_TABLE_NAME.to_owned(),
        item: store_map,
        ..Default::default()
    };
    let put_output = client.put_item(put_input).await;
    if put_output.is_err() {
        return Err(format!("Error CCDB79: {:?}", put_output.unwrap_err()));
    }
    return Ok(());
}


/**
 * Generates a store ID that is not being used.
 * Returns error if there is an error
 * On success, returns (StoreId, HashMap with StoreId in it)
 */
pub async fn generate_store_id(client: DynamoDbClient, short: &str) -> Result<(String, HashMap<String, AttributeValue>),String> {

    // the following code just generates a new license code and empty map
    // since the user does not exist
    
    
    let dict = "BCDFGHJLMNPQRSTVWXYZ256789".as_bytes();

    // this variable is theoretically slightly more efficient 
    // than calling dict.len() repeatedly
    let dict_len = dict.len();


    let clean = cleanse(short, "", true);
    let shorter = clean.substring(0, 5);



    let mut exists = true;
    let mut company_id_string = "".to_owned();

    let mut company_id_map: HashMap<String, AttributeValue> = HashMap::new();

    // this will generate license codes until it determines that it has
    // generated an unused license code
    while exists {
        let mut result = shorter.to_owned();
        // block is used to prevent RNG code from interfering with
        // the async code
        {
            let mut rng = rand::thread_rng();
            while result.len() != 12 {
                result.push(dict[rng.gen_range(0..dict_len)] as char);
            }
        }
        

        let encrypted_company_id = encrypt_company_id(&result);
        
        // reset the license_map if the last license generated exists
        if company_id_map.contains_key("id1") {
            company_id_map = HashMap::new();
        }
        
        company_id_map.insert(
            "id".to_owned(),
            AttributeValue {
                s: Some(encrypted_company_id.to_owned()),
                ..Default::default()
            }
        );
        company_id_string = result.to_owned();
        
        let get_company_input = &client.get_item(
            GetItemInput {
                table_name: COMPANY_TABLE_NAME.to_owned(),
                key: company_id_map.to_owned(),
                consistent_read: Some(true),
                ..Default::default()
            }
        ).await;

        if get_company_input.is_err() {
            return Err(format!("Error 323: {}", get_company_input.as_ref().unwrap_err().to_string()));
        }

        let get_company_item = get_company_input.as_ref().unwrap().item.as_ref();
        if get_company_item.is_none() {
            exists = false;
        }
    }

    return Ok((company_id_string, company_id_map.to_owned()));
}