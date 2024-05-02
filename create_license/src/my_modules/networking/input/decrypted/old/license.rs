/**
 * Inserts license info into License and User items
 */

/*
use std::collections::HashMap;

use rusoto_dynamodb::AttributeValue;

use crate::my_modules::{networking::output::error::HttpError, utils::maps::Maps};

use super::Decrypted;

impl Decrypted {
    pub async fn _license(&mut self, user_item: HashMap<String, AttributeValue>) -> Result<(), HttpError> {
        let mut license_item = self.license_item.as_ref().unwrap();
        let license_plugins_map_res = license_item.get_m("Plugins", "Error CLML15");
        if license_plugins_map_res.as_ref().is_err() {
            return Err(license_plugins_map_res.unwrap_err());
        }
        let license_plugins_map = license_plugins_map_res.unwrap();

        let user_item_opt = self.user_item.as_ref();
        if user_item_opt.is_none() {
            return Err((500, "Error CLNIDL23").into());
        }
        let mut user_item = user_item_opt.unwrap();
        let user_license_map_res = user_item.get_m("licenses", "Error CLNIDL26");
        if user_license_map_res.as_ref().is_err() {
            return Err(user_license_map_res.unwrap_err());
        }
        let mut user_plugins_map = user_license_map_res.unwrap();

        for plugin in self.products_info.iter() {
            // insert license info into license_map
            if 
            // insert license info into user map
        }
        return Ok(());
    }
}

*/