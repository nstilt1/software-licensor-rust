use std::collections::HashMap;
use rusoto_dynamodb::AttributeValue;

use crate::{OptionHandler, error::ApiError};

pub static S: char = 's';
pub static N: char = 'n';

pub trait Maps {
    /// Insert a String or a Number into a hashmap, use S or N to pick
    /// Returns None if data was not overwritten
    /// Returns Some if data was overwritten
    fn insert_data(&mut self, key: &str, data: &str, t: char) -> Option<AttributeValue>;

    /// Inserts license info into a License item hashmap
    fn insert_license(
        &mut self, 
        custom_success: Option<String>, 
        first_name: &str, 
        last_name: &str, 
        license_type: &str, 
        machines_allowed: u16,
        order_number: &str,
        should_increase: bool
    ) -> Result<HashMap<String, AttributeValue>, ApiError>;

    /// Insert a bool into a map
    fn insert_bool(&mut self, key: &str, data: Option<bool>);

    /// Insert binary data into a map
    fn insert_binary(&mut self, key: &str, data: &[u8]);

    /// Insert a map into a map. Leave empty to add a new map
    fn insert_map(&mut self, key: &str, data:Option<HashMap<String, AttributeValue>>);
    
    /// Gets a string or a number from a hashmap.
    fn get_data(&self, key: &str, t: char) -> Result<String, ApiError>;

    /// Get a Map from the hashmap, or return an error
    fn get_m(&self, key: &str) -> Result<HashMap<String, AttributeValue>, ApiError>;
    
    /// Returns a hashmap filled with any String Primary keys
    /// Supply it with a vec of (PrimaryKeyId, PrimaryKeyValue)
    fn insert_strings(&mut self, keys: Vec<(&str, &str)>) -> Self;

    fn new_map(keys: Vec<(&str, &str)>) -> Self;

    /// Increase a number in a hashmap
    /// or insert the number if it doesn't exist
    fn increase_number(&mut self, key: &str, to_add: u16) -> Result<(), ApiError>;

    fn increase_float(&mut self, key: &str, to_add: &str) -> Result<(), ApiError>;

    /// Insert a string into a hashmap, or append it to the existing one, separated by commas
    fn append_string(&mut self, key: &str, to_add: &str) -> Result<(), ApiError>;

    /// Get a list from a hashmap, returns error if not found.
    fn get_l(&self, key: &str) -> Result<Vec<AttributeValue>, ApiError>;

    /// Insert a List into a hashmap, or overwrite one.
    /// 
    /// Leave to_add empty for a blank list
    fn insert_l(&mut self, key: &str, to_add: Option<Vec<AttributeValue>>);
}

pub trait GetOrMutateHashmap<T> {
    fn key_should_exist(&self, key: &str) -> Result<&T, ApiError>;
}
impl<T> GetOrMutateHashmap<T> for HashMap<String, T> {
    fn key_should_exist(&self, key: &str) -> Result<&T, ApiError> {
        if let Some(t) = self.get(key) {
            Ok(t)
        } else {
            Err(ApiError::InvalidDbSchema(format!("Error: Key {} not found", key)))
        }
    }
}

impl Maps for HashMap<String, AttributeValue> {
    fn get_l(&self, key: &str) -> Result<Vec<AttributeValue>, ApiError> {
        let attribute_value = self.key_should_exist(key)?;
        attribute_value.l.should_exist_in_db_schema(key).cloned()
    }

    fn insert_l(&mut self, key: &str, to_add: Option<Vec<AttributeValue>>) {
        let to_insert: Vec<AttributeValue>;
        if to_add.is_some(){to_insert = to_add.unwrap();}
        else{to_insert = Vec::new();}

        self.insert(key.to_owned(), AttributeValue { l: Some(to_insert), ..Default::default()});
    }

    fn insert_binary(&mut self, key: &str, data: &[u8]) {
        self.insert(
            key.to_string(),
            AttributeValue {
                b: Some(data.to_vec().into()),
                ..Default::default()
            }
        );
    }

    fn append_string(&mut self, key: &str, to_add: &str) -> Result<(), ApiError> {
        let existed = self.insert_data(&key, &to_add.to_string(), S);
        if existed.as_ref().is_some(){
            let old_result = existed.as_ref().unwrap().s.as_ref().unwrap();
            self.insert_data(&key, &format!("{},{}", &old_result, &to_add), S);
        }
        return Ok(());
    }

    fn increase_float(&mut self, key: &str, to_add: &str) -> Result<(), ApiError> {
        // inserting data returns the current value, which works well for incrementing
        let existing_value = self.insert_data(&key, &to_add.to_string(), N);
        if existing_value.as_ref().is_some(){
            let existing_value = existing_value
                .should_exist_in_db_schema(key)?
                .n
                .should_exist_in_db_schema(key)?
                .parse::<f64>()?;
            let to_add = to_add.parse::<f64>()?;
            
            self.insert_data(&key, &(existing_value+to_add).to_string(), N);
        }
        return Ok(());
    }

    fn increase_number(&mut self, key: &str, to_add: u16) -> Result<(), ApiError> {
        let existing_value = self.insert_data(&key, &to_add.to_string(), N);
        if existing_value.as_ref().is_some(){
            let existing_value = existing_value
            .should_exist_in_db_schema(key)?
            .n
            .should_exist_in_db_schema(key)?
            .parse::<u16>()?;
            
            self.insert_data(&key, &(to_add+existing_value).to_string(), N);
        }
        return Ok(());

    }

    fn new_map(keys: Vec<(&str, &str)>) -> Self {
        return HashMap::new().insert_strings(keys);
    }

    fn insert_license(
            &mut self, 
            custom_success: Option<String>, 
            first_name: &str, 
            last_name: &str, 
            license_type: &str, 
            machines_allowed: u16,
            order_number: &str,
            should_increase: bool
    ) -> Result<HashMap<String, AttributeValue>, ApiError> {
        let cust_success: &str;
        if custom_success.is_none() {
            cust_success = "";
        }else{
            cust_success = custom_success.as_ref().unwrap();
        }
        let mut result =  self.insert_strings(vec![
            ("ActivationTime", "0"),
            ("CustomSuccess", cust_success),
            ("ExpiryTime", "0"),
            ("FirstName", first_name),
            ("LastName", last_name),
            ("LicenseType", license_type),
            ("OrderID", order_number)
        ]).to_owned();

        if should_increase {
            let f = result.increase_number("MachinesAllowed", machines_allowed);
            if f.as_ref().is_err() {return Err(f.unwrap_err());};
        }else{
            result.insert_data("MachinesAllowed", machines_allowed.to_string().as_str(), N);
        }
        result.insert_bool("LicenseActive", Some(true));
        
        result.insert(
            "Offline".to_owned(),
            AttributeValue {
                l: Some(Vec::new()),
                ..Default::default()
            }
        );
        result.insert(
            "Online".to_owned(),
            AttributeValue {
                l: Some(Vec::new()),
                ..Default::default()
            }
        );
        result.insert_bool("SubscriptionActive", Some(true));

        return Ok(result);
        
    }
    fn get_data(&self, key: &str, t: char) -> Result<String, ApiError>{
        let attribute_value = self.key_should_exist(key)?;
        let data = match t {
            's' => &attribute_value.s,
            'n' => &attribute_value.n,
            _ => return Err(ApiError::ServerError("Incorrect data type for AttributeValue in Maps::get_data".into()))
        };
        let data = data.should_exist_in_db_schema(key)?;
        return Ok(data.to_owned());
    }
    fn insert_strings(&mut self, keys: Vec<(&str, &str)>) -> Self {
        for key in keys {
            self.insert_data(&key.0, &key.1, S);
        }
        return self.to_owned();
    }
    fn get_m(&self, key: &str) -> Result<HashMap<String, AttributeValue>, ApiError> {
        let opt = self.key_should_exist(key)?;
        opt.m.should_exist_in_db_schema(key).cloned()
    }

    fn insert_data(&mut self, key: &str, data: &str, t: char) -> Option<AttributeValue> {
        let result: Option<AttributeValue>;
        result = match t {
            's' => self.insert(
                    key.to_string(),
                    AttributeValue {
                        s: Some(data.to_string()),
                        ..Default::default()
                    }
            ),
            'n' => self.insert(
                    key.to_string(),
                    AttributeValue {
                        n: Some(data.to_string()),
                        ..Default::default()
                    }
                ),
            _ => None,
        };
        return result;
    } 
    fn insert_bool(&mut self, key: &str, data: Option<bool>) {
        self.insert(
            key.to_owned(),
            AttributeValue {
                bool: data,
                ..Default::default()
            }
        );
    }
    fn insert_map(&mut self, key: &str, data:Option<HashMap<String, AttributeValue>>) {
        if data.as_ref().is_some() {
            self.insert(
                key.to_owned(),
                AttributeValue {
                    m: data.to_owned(),
                    ..Default::default()
                }
            );
        }else{
            self.insert(
                key.to_owned(),
                AttributeValue {
                    m: if data.as_ref().is_some() {
                        data.to_owned()
                    }else{
                        Some(HashMap::new())
                    },
                    ..Default::default()
                }
            );
        }
    }
}