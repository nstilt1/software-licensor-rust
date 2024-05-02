
/*
use std::collections::HashMap;
use rusoto_dynamodb::{AttributeValue};
use crate::my_modules::{utils::maps::*, networking::output::error::HttpError};

use super::Decrypted;

impl Decrypted {
    pub fn get_user_license_maps(&self, existing_license_maps: Option<HashMap<String, AttributeValue>>) -> Result<HashMap<String, AttributeValue>, HttpError> {

        let mut license_map: HashMap<String, AttributeValue>;
        // get the current license map if it exists, otherwise make an empty one
        if self.user_item.is_some() {
            let user_map = self.user_item.unwrap();
            let license_map_result = user_map
                .get_m("Plugins", "CLMRGM328");

            if license_map_result.as_ref().is_err() {
                return Err(license_map_result.unwrap_err());
            }

            license_map = license_map_result.unwrap().to_owned();
        }else{
            license_map = HashMap::new();
        }

        if self.plugin_items.is_none() {
            return Err((403, "Forbidden").into());
        }
        let plugin_items = self.plugin_items.unwrap();
        // add plugin info to the map
        for plugin in self.products_info {
            // get the base machine limit for the plugin
            if !plugin_items.contains_key(&plugin.id) {
                return Err((500, "Error CLMR375p").into());
            }
            let plugin_map_opt = plugin_items.get(&plugin.id);
            if plugin_map_opt.is_none() {
                return Err((500, "Error CLMR379").into());
            }
            let plugin_map = plugin_map_opt.unwrap();

            let base_machine_limit_result = plugin_map.get_data("MaxMachinesPerLicense", N);
            if base_machine_limit_result.as_ref().is_err() {
                return Err(base_machine_limit_result.unwrap_err());
            }

            let base_machine_limit_r = base_machine_limit_result.unwrap().parse::<u32>();
            if base_machine_limit_r.is_err() {
                return Err((500, "Error CLMR390d").into());
            }
            let base_machine_limit = base_machine_limit_r.unwrap();

            license_map.insert_license(
                None, 
                &self.first_name.unwrap(), 
                &self.first_name.unwrap(), 
                &plugin.license_type, 
                &(base_machine_limit * &plugin.quantity.parse::<u32>().unwrap()).to_string(),
                &self.order_number
            );

        }
        return Ok(license_map);
    }
}

*/