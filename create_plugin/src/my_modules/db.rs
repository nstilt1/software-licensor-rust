use rusoto_dynamodb::{DynamoDbClient, DynamoDb, AttributeValue, GetItemInput, PutItemInput, BatchWriteItemInput, WriteRequest, PutRequest};
use std::collections::HashMap;
use rand::prelude::*;

use substring::Substring;
use regex::Regex;

use super::{crypto::custom::{encrypt_plugin_id, encrypt_company_id}, utils::{maps::*, utils::cleanse}, error::HttpError};

static COMPANY_TABLE_NAME: &str = "Companies";
static PLUGINS_TABLE_NAME: &str = "Plugins";


/**
 * Generates a plugin ID that is not being used.
 * Returns error if there is an error
 * On success, returns decrypted, encrypted Plugin ID string
 */
pub async fn generate_plugin_id(
    client: DynamoDbClient, 
    company_id: &str, 
    plugin_name: &str, 
    plugins_map_opt: Option<&AttributeValue>) 
-> Result<(String,String), (u16, String)> {

    if plugins_map_opt.is_none() {
        return Err((400, "Error CPDBGP18".to_owned()));
    }
    let plugins_map_opt_z = plugins_map_opt.unwrap().m.as_ref();
    if plugins_map_opt_z.is_none() {
        return Err((500, "Error CPDB31d".to_owned()));
    }
    let plugins_map = plugins_map_opt_z.unwrap().to_owned();


    // the following code just generates a new license code and empty map
    // since the user does not exist
    
    
    let dict = "BCDFGHJLMNPQRSTVWXYZ256789".as_bytes();

    // this variable is theoretically slightly more efficient 
    // than calling dict.len() repeatedly
    let dict_len = dict.len();

    // remove non alphabetic characters and take first 5 characters
    //let re = Regex::new(r"[^a-zA-Z]").unwrap();
    //let cleansed_plugin_name = format!("{} ", &re.replace_all(&plugin_name.to_ascii_uppercase(), ""));
    let cleansed_plugin_name = cleanse(&plugin_name, "", true);
    let short_id = cleansed_plugin_name.substring(0, 5);


    let mut exists = true;
    let mut encrypted_plugin_id = "".to_owned();
    let mut decrypted_plugin_id = "".to_owned();

    let mut plugin_id_map: HashMap<String, AttributeValue> = HashMap::new();

    // this will generate license codes until it determines that it has
    // generated an unused license code
    while exists {
        decrypted_plugin_id = short_id.to_string();
        // block is used to prevent RNG code from interfering with
        // the async code
        {
            let mut rng = rand::thread_rng();
            while decrypted_plugin_id.len() != 11 {
                decrypted_plugin_id.push(dict[rng.gen_range(0..dict_len)] as char);
            }
        }
        

        encrypted_plugin_id = encrypt_plugin_id(&company_id, &decrypted_plugin_id);

        // only check database if the plugins map doesn't include the new ID, otherwise, it restarts the loop
        if !plugins_map.contains_key(&encrypted_plugin_id) {

            // reset the license_map if the last license generated exists
            if plugin_id_map.contains_key("id") {
                plugin_id_map = HashMap::new();
            }
            
            plugin_id_map.insert(
                "id".to_owned(),
                AttributeValue {
                    s: Some(encrypted_plugin_id.to_owned()),
                    ..Default::default()
                }
            );
            
            let get_plugin_input = &client.get_item(
                GetItemInput {
                    table_name: PLUGINS_TABLE_NAME.to_owned(),
                    key: plugin_id_map.to_owned(),
                    consistent_read: Some(true),
                    ..Default::default()
                }
            ).await;

            if get_plugin_input.is_err() {
                return Err((500, format!("Error 323: {}", get_plugin_input.as_ref().unwrap_err().to_string())));
            }

            let get_plugin_item = get_plugin_input.as_ref().unwrap().item.as_ref();
            if get_plugin_item.is_none() {
                exists = false;
            }
        }
    }

    return Ok((decrypted_plugin_id, encrypted_plugin_id.to_owned()));
}


/**
 * Creates a plugin in the plugin table.
 * Creates an entry in the store item's plugins map
 * Returns the plugin id or an error.
 */
pub async fn create_plugin(
    client: DynamoDbClient, 
    company_id: &str, 
    plugin_name: &str,
    company_map: HashMap<String, AttributeValue>,
    partial_plugin_map: HashMap<String, AttributeValue>) 
-> Result<String, HttpError> {

    // generate plugin ID
    let plugin_id_result = generate_plugin_id(client.to_owned(), &company_id, &plugin_name, company_map.get("plugins")).await;
    if plugin_id_result.is_err() {
        return Err(plugin_id_result.unwrap_err().into());
    }

    let plugin_id_tuple = plugin_id_result.unwrap();
    let decrypted_plugin_id = plugin_id_tuple.0;
    let encrypted_plugin_id = plugin_id_tuple.1;

    // create a plugin
    let mut new_plugin_item_map = partial_plugin_map.to_owned();
    new_plugin_item_map.insert_data("id", &encrypted_plugin_id, S);

    let plugin_item_write_request = WriteRequest {
        put_request: Some(PutRequest {item: new_plugin_item_map.to_owned()}),
        ..Default::default()
    };

    // add plugin index to company's `plugins` map
    let mut new_company_map = company_map.to_owned();
    let previous_plugins_data_result = new_company_map.get_m("plugins", "CPDB138");
    if previous_plugins_data_result.is_err() {
        return Err(previous_plugins_data_result.unwrap_err());
    }
    let mut new_plugins_data = previous_plugins_data_result.unwrap();
    new_plugins_data.insert(decrypted_plugin_id.to_owned(), AttributeValue {m: Some(HashMap::new()), ..Default::default()});

    new_company_map.insert("plugins".to_owned(), AttributeValue {m: Some(new_plugins_data.to_owned()), ..Default::default()});

    // finish write request
    let company_item_write_request = WriteRequest {
        put_request: Some(PutRequest { item: new_company_map.to_owned()}),
        ..Default::default()
    };

    let mut write_items: HashMap<String, Vec<WriteRequest>> = HashMap::new();
    write_items.insert(COMPANY_TABLE_NAME.to_owned(), vec![company_item_write_request.to_owned()]);
    write_items.insert(PLUGINS_TABLE_NAME.to_owned(), vec![plugin_item_write_request.to_owned()]);

    let batch_write_items = BatchWriteItemInput {
        request_items: write_items.to_owned(),
        ..Default::default()
    };

    let batch_write_output = client.batch_write_item(batch_write_items).await;

    if batch_write_output.is_err() {
        return Err(format!("Error CPDB164: {:?}", batch_write_output.unwrap_err()).into());
    }

    // return plugin_id and license_types in json format

    return Ok(decrypted_plugin_id.to_string());

}

/**
 * Gets the company item, or returns an error.
 * Parameters: 
 * * dynamoDBClient
 * * companyID
 */
pub async fn get_company(client: DynamoDbClient, company_id: &str) -> Result<HashMap<String, AttributeValue>, (u16, String)> {
    let mut company_id_map: HashMap<String, AttributeValue> = HashMap::new();
    company_id_map.insert(
        "id".to_owned(),
        AttributeValue {
            s: Some(encrypt_company_id(&company_id)),
            ..Default::default()
        }
    );

    let get_input = client.get_item(
        GetItemInput {
            consistent_read: Some(true),
            key: company_id_map.to_owned(),
            table_name: COMPANY_TABLE_NAME.to_owned(),
            ..Default::default()
        }
    ).await;

    if get_input.is_err() {
        return Err((500, "Error CPD29".to_owned()));
    }
    let get_company_opt = get_input.unwrap().item;
    if get_company_opt.is_none() {
        return Err((400, "Error: Company not found.".to_owned()));
    }
    return Ok(get_company_opt.unwrap().to_owned());
}

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
pub async fn generate_store_id(client: DynamoDbClient) -> Result<(String, HashMap<String, AttributeValue>),String> {

    // the following code just generates a new license code and empty map
    // since the user does not exist
    
    
    let dict = "BCDFGHJLMNPQRSTVWXYZ256789".as_bytes();

    // this variable is theoretically slightly more efficient 
    // than calling dict.len() repeatedly
    let dict_len = dict.len();


    


    let mut exists = true;
    let mut company_id_string = "".to_owned();

    let mut company_id_map: HashMap<String, AttributeValue> = HashMap::new();

    // this will generate license codes until it determines that it has
    // generated an unused license code
    while exists {
        let mut result = "".to_owned();
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
        company_id_string = encrypted_company_id.to_owned();
        
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