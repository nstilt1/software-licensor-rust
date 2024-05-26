use std::collections::HashMap;
use aws_sdk_dynamodb::types::AttributeValue;

use crate::{error::ApiError, tables::Item, OptionHandler};

use super::maps_mk2::AttrValAbstraction;

pub static S: char = 's';
pub static N: char = 'n';

pub trait Maps {
    /// Insert a String or a Number into a hashmap, use S or N to pick
    /// Returns None if data was not overwritten
    /// Returns Some if data was overwritten
    fn insert_data(&mut self, key: &str, data: &str, t: char) -> Option<AttributeValue>;

    /*
    /// Inserts license info into a License item hashmap
    fn insert_license(
        &mut self, 
        custom_success: Option<String>, 
        first_name: &str, 
        last_name: &str, 
        license_type: &str, 
        machines_allowed: u32,
        order_number: &str,
        should_increase: bool
    ) -> Result<HashMap<String, AttributeValue>, ApiError>;
    */

    /// Insert a bool into a map
    fn insert_bool(&mut self, key: &str, data: Option<bool>);

    /// Returns a hashmap filled with any String Primary keys
    /// Supply it with a vec of (PrimaryKeyId, PrimaryKeyValue)
    fn insert_strings(&mut self, keys: Vec<(&str, &str)>) -> Self;

    fn new_map(keys: Vec<(&str, &str)>) -> Self;

    /// Increase a number in a hashmap
    /// or insert the number if it doesn't exist
    fn increase_number<T: AttrValAbstraction>(&mut self, key: &Item<T>, to_add: u64) -> Result<u64, ApiError>;

    fn increase_float(&mut self, key: &str, to_add: &str) -> Result<(), ApiError>;
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
    fn increase_float(&mut self, key: &str, to_add: &str) -> Result<(), ApiError> {
        // inserting data returns the current value, which works well for incrementing
        let existing_value = self.insert_data(&key, &to_add.to_string(), N);
        if existing_value.as_ref().is_some(){
            let existing_value = existing_value
                .should_exist_in_db_schema(key)?
                .as_n()
                .unwrap()
                .parse::<f64>()?;
            let to_add = to_add.parse::<f64>()?;
            
            self.insert_data(&key, &(existing_value+to_add).to_string(), N);
        }
        return Ok(());
    }

    fn increase_number<T: AttrValAbstraction>(&mut self, item: &Item<T>, to_add: u64) -> Result<u64, ApiError> {
        let existing_value = self.insert_data(&item.key, &to_add.to_string(), N);
        let sum = if existing_value.as_ref().is_some(){
            let existing_value = existing_value
            .should_exist_in_db_schema(item.key)?
            .as_n()
            .unwrap()
            .parse::<u64>()?;
            let s = to_add + existing_value;
            self.insert_data(&item.key, &(s).to_string(), N);
            s
        } else {
            to_add
        };
        return Ok(sum);

    }

    fn new_map(keys: Vec<(&str, &str)>) -> Self {
        return HashMap::new().insert_strings(keys);
    }
    /*
    fn insert_license(
            &mut self, 
            custom_success: Option<String>, 
            first_name: &str, 
            last_name: &str, 
            license_type: &str, 
            machines_allowed: u32,
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
    */
    fn insert_strings(&mut self, keys: Vec<(&str, &str)>) -> Self {
        for key in keys {
            self.insert_data(&key.0, &key.1, S);
        }
        return self.to_owned();
    }

    fn insert_data(&mut self, key: &str, data: &str, t: char) -> Option<AttributeValue> {
        let result: Option<AttributeValue>;
        result = match t {
            's' => self.insert(
                    key.to_string(),
                    AttributeValue::S(data.to_string())
            ),
            'n' => self.insert(
                    key.to_string(),
                    AttributeValue::N(data.to_string())
                ),
            _ => None,
        };
        return result;
    } 
    fn insert_bool(&mut self, key: &str, data: Option<bool>) {
        self.insert(
            key.to_owned(),
            AttributeValue::Bool(data.unwrap())
        );
    }
}