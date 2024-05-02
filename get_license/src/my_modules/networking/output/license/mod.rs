use std::collections::HashMap;

use rusoto_dynamodb::AttributeValue;

use serde::{Serialize, Deserialize};
use utils::{dynamodb::maps::Maps, error::ApiError, OptionHandler};

use crate::my_modules::utils::maps::{N, S};


#[derive(Serialize, Deserialize, Debug)]
pub struct Machine {
    id: String,
    computer_name: String,
    os: String,
}
impl Machine {
    #[inline]
    pub fn new(new_id: &str, c_name: &str, new_os: &str) -> Self {
        Machine {
            id: new_id.to_string(),
            computer_name: c_name.to_string(),
            os: new_os.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Plugin {
    id: String,
    machines: Vec<Machine>,
    max_machines: String,
    license_type: String,
}
impl Plugin {
    #[inline]
    pub fn new(new_id: &str, machine_limit: &str, l_type: &str) -> Self {
        Plugin {
            id: new_id.to_owned(),
            machines: Vec::new(),
            max_machines: machine_limit.to_owned(),
            license_type: l_type.to_owned(),
        }
    }

    #[inline]
    pub fn add_machine(&mut self, machine: Machine) {
        self.machines.push(machine);
    }

    #[inline]
    pub fn add_machines(&mut self, map: HashMap<String, AttributeValue>) -> Result <(), ApiError> {
        for (mach_id, value) in map {
            let node = value.m.should_exist_in_db_schema(&mach_id)?;
            let computer_name = node.get_data("computer_name", S)?;
            let os = node.get_data("os", S)?;
            self.add_machine(Machine::new(&mach_id, &computer_name, &os));
        }
        return Ok(());
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct License {
    code: String,
    plugins: Vec<Plugin>,
}
impl License {
    pub fn new(new_code: &str) -> Self {
        License {
            code: new_code.to_string(),
            plugins: Vec::new(),
        }
    }
    /**
     * Create a filled License Object with 3 lines.
     */
    pub fn init_license(new_code: &str, user_licenses_map: HashMap<String, AttributeValue>) -> Result<License, ApiError> {
        let mut new_license = License::new(new_code);
        for (plugin_id, value) in user_licenses_map {
            let node = value.m.as_ref().unwrap().to_owned();
            let max_machines = node.get_data("maxMachines", N)?;
            let license_type = node.get_data("license_type", S)?;
            let mut plugin = Plugin::new(&plugin_id, &max_machines, &license_type);
            let machine_map = node.get_m("machines")?;
            
            plugin.add_machines(machine_map)?;
            new_license.add_plugin(plugin);
        }

        return Ok(new_license);
    }
    pub fn add_plugin(&mut self, plugin: Plugin) {
        self.plugins.push(plugin);
    }
}