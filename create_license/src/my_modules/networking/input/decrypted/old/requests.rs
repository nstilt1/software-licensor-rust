use std::{time::{SystemTime, UNIX_EPOCH}, collections::HashMap};

use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDbClient, DynamoDb, GetItemInput, AttributeValue, BatchGetItemInput, KeysAndAttributes};
use serde::{Serialize, Deserialize};
use serde_json::*;
use std::result::Result;

use crate::my_modules::{
    crypto::{
        rsa::*, aes::*, sha::*, custom::*}, 
    utils::{
        batch_get_utils::*, maps::*, utils::*},
        db::*};

use super::{DecryptedRequest, Initial, Product};

//use super::{rsa::*, aes::aes_decrypt, db::*, maps::*, utils::{hash_email, decrypt_plugin_id}, batch_get_utils::BatchGetUtils};

static USERS_TABLE_NAME: &str = "PluginUsers";
static PLUGINS_TABLE_NAME: &str = "Plugins";



impl DecryptedRequest {
    
    

    
    

    


    

    

    

    
}


impl Initial {
    pub fn new(json: &str) -> Result<Self, (u16, String)> {
        let serde_result: Result<Initial, serde_json::Error> = serde_json::from_str(json);
        if serde_result.as_ref().is_err() {
            return Err((400, format!("Error: {:?}", serde_result.unwrap_err())));
        }
        return Ok(serde_result.unwrap());
    }

    pub async fn validate(&self) -> Result<DecryptedRequest, (u16, String)> {
        let current_time = SystemTime::duration_since (&SystemTime::now(), UNIX_EPOCH).unwrap().as_secs();
        if self.timestamp.parse::<u64>().unwrap() < current_time - 300 {
            return Err((400, "Error: Timestamp invalid".to_owned()));
        }
        let signature = self.signature.to_owned();
        let signed_stuff = format!("{}{}{}{}", self.data, self.nonce, self.key, self.timestamp);
        let result = DecryptedRequest::new(self).await;
        if result.as_ref().is_err() {
            return Err(result.unwrap_err());
        }
        
        let mut req = result.unwrap().validate(&signature, &signed_stuff).await?;
        let mut user = req.check_user().await?;
        //user.insert_license_data()

        return Err(());
    }
}