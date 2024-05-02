use std::num::{ParseFloatError, ParseIntError};
use std::collections::HashMap;

use base64::{engine::general_purpose, Engine};
use num_traits::Num;
use rusoto_dynamodb::AttributeValue;
use serde::{Serialize, Deserialize};
use substring::Substring;

use super::crypto::custom::encrypt_company_id;
use super::error::HttpError;
use super::utils::utils::{cleanse, Comparing};
use super::utils::{maps::*};

#[derive(Serialize, Deserialize, Debug)]
pub struct AesData {
    pub store_id: String,
    pub company_index: Option<String>,
    pub plugin_id_prefix: String,
    licensing_method: String,
    juce_private_key: Option<String>,
    juce_public_key: Option<String>,
    language_support: Vec<LanguageSupport>,
    enabled_license_types: Vec<LicenseType>,
    machine_limit: String,
    version: String,
    pub juce_public_full: Option<String>,
    is_offline_enabled: Option<bool>,
    is_online_enabled: Option<bool>
}
impl AesData {

    /**
     * Gets the short plugin id
     */
    pub fn get_short_plugin_id(&self) -> String {
        return cleanse(&self.plugin_id_prefix, "", true).substring(0, 5).to_owned();
    }

    /**
     * Validates and converts some data for use in the database
     */
    pub fn validate(&mut self) -> Result<(), (u16, String)> {
        
        let mut error = "".to_owned();
        let mut error_code = 200;


        let accepted_licensing_methods = vec!["juce"];
        if !accepted_licensing_methods.contains(&self.licensing_method.to_lowercase().as_str()) {
            error.push_str(&format!("\nError: Invalid licensing method. We currently only support {}", accepted_licensing_methods.join(", ")));
            error_code = 400;
        }


        // validate machine limit
        let machine_limit_parsed: Result<u16, ParseIntError> = self.machine_limit.parse();
        if machine_limit_parsed.is_err() {
            error.push_str("\nError: Machine limit is not a u16.");
            error_code = 400;
        }
        let machine_limit_u32 = machine_limit_parsed.unwrap();
        if machine_limit_u32 < 1 || machine_limit_u32 > 200 {
            error.push_str("\nError: Machine limit must be at least 1 and less than 200");
            error_code = 400;
        }

        // validate the enabled license types
        let mut license_types: Vec<String> = Vec::new();
        for license_type in self.enabled_license_types.iter_mut() {
            match license_type.type_name.to_lowercase().as_str() {
                "offline" => {self.is_offline_enabled = Some(true);},
                "online" => {self.is_online_enabled = Some(true);},
                _ => {}, 
            }
            // check if multiple license_types with the same type are found
            if license_types.contains(&license_type.type_name.to_lowercase()){
                error_code = 400;
                error.push_str(&format!("\nError: Duplicate entry for {:?} license type. Only one entry per license type is allowed.", &license_type.type_name));
            }else{
                license_types.push(license_type.type_name.to_lowercase());
                license_type.type_name = license_type.capitalize();
            }

            let validation_result = license_type.validate();
            if validation_result.is_err(){
                error.push_str(&validation_result.unwrap_err());
            }
            
        }
        if self.is_offline_enabled.is_none() {
            self.is_offline_enabled = Some(false);
        }
        if self.is_online_enabled.is_none() {
            self.is_online_enabled = Some(false);
        }

        // validate the language support
        for language in &self.language_support {
            // check if multiple entries exist for the same language
            let mut languages_vec: Vec<String> = Vec::new();
            if languages_vec.contains(&language.language_name.to_lowercase()) {
                error.push_str(&format!("\nError: {:?} language entry appears more than once.", &language.language_name));
                error_code = 400;
            }else{
                languages_vec.push(language.language_name.to_lowercase());
            }

            let validation_result = language.validate();
            if validation_result.is_err(){
                error.push_str(&validation_result.unwrap_err());
                error_code = 400;
            }
        }

        // validate and encode the keys to be stored in the database later on
        // key will be in the form of [512 hexadecimal digits],[512 hexadecimal digits]
        let encoded_keys_result = &self.encode_keys();
        if encoded_keys_result.as_ref().is_err() {
            let error_tuple = encoded_keys_result.as_ref().unwrap_err();
            error.push_str(&error_tuple.1);
            // elevate the error code if needed
            if error_code < error_tuple.0 {
                error_code = error_tuple.0;
            }
        }else{
            let encoded_keys_tuple = encoded_keys_result.as_ref().unwrap();
            self.juce_public_key = Some(encoded_keys_tuple.0.to_owned());
            self.juce_private_key = Some(encoded_keys_tuple.1.to_owned());

        }

        // set the company id to the value in the database
        self.company_index = Some(encrypt_company_id(&self.store_id));

        if error.len() > 1 {
            return Err((error_code, error.to_owned()));
        }
        return Ok(());
    }

    /**
     * If the keys are present, it checks if they are valid, and it returns the 
     * base64 encoded keys.
     * (private, public)
     *      if the keys aren't valid, it returns the error message(s)
     * If the keys are not present, it returns the default public and private keys
     * 
     * Returns (Public Part1, PrivateKey) or the reason why the error occured
     */
    pub fn encode_keys(&mut self) -> Result<(String, String), (u16, String)> {
        let private_option = self.juce_private_key.to_owned();
        let public_option = self.juce_public_key.to_owned();
        if private_option.is_none() || public_option.is_none() {
            // return default keys
            let public_key = "11".to_owned();
            let private_key = "587a57ed3db98c3d9b54c31a8f0e3aaf4df917cf5add11f8d0f23d13636b6945716f708512f0ca098d3ccec74458e462f7b2974e3ac6bdfdda2968bf196a8c95029f082f8e4ca850ff84d3babd6c220c302291190975d47e8b31fa94d290c77ac82ef11fb138942ad5d5faa38ca1bd631bba0bd47abe85f3e2a353a51f181d7f44cc80b52381010233b798fe3682159474b926de723f9582afe0b2af3540954cf72e25e16d31aa55c2b924ebac615f279adfbbfa0adc3f1c135fd7c1c0e25fb221ea4b66cafc36a2715f9f5fd47bbb0fb267231ebcc718437e2d2e7b9b0fb5ea093961f7e30649610d40b0934f0c3933d20779e1774dc3474528f75307ffd0b1,73b3ae0eda902d8ba3bd9cac93b0255b65f6f7c06321178073b2ed681f8c75f85942f59a53d86aaa0776e70494743e5a08d5d98daf52a9ae6c0ec40d9763f2ea3e813216cdc6b4b8b09a012f4679b65eb51982aa96379fb92c2daa25135add792d29b17836851086c8dcbde99084bc954ba4859fb4343903d99a81130146eb806bfca303df53533aa8155ce7c70fba8c245d03a712d555be15ef8a9520b7fec63aaf3f86306da9790e004b31b3deab1340869b2bd401a0238571149f956bde2897bb8bc4aef486938549a437e2c9da3ad3a51c584bbd8415c35c1477b437285a39086d910b4282317e704593e83e74793401d8009de78024159b2fb5887d5a5d".to_owned();

            let comma = private_key.find(',');
            if comma.is_none() {
                // if this error occurs, something is very wrong
                return Err((500, "\nError CPLR85".to_owned()));
            }
            let p1 = private_key.substring(0, comma.unwrap());
            let p2 = private_key.substring(comma.unwrap(), private_key.len());

            if self.juce_public_full.is_none() {
                self.juce_public_full = Some(format!("{},{}", &public_key, &p2));
            }
    
            let p1_big = num_bigint::BigUint::from_str_radix(&p1, 16);
            let p2_big = num_bigint::BigUint::from_str_radix(&p2, 16);

            if p1_big.is_err() {
                return Err((422, format!("\nError CPLR90: This is probably due to bad input, but it could be an issue on our end. Make sure the keys are exactly how they are outputted with JUCE, or you can use the defaults by leaving the JUCE Keys empty. More: {:?}", p1_big.unwrap_err())));
            }
            if p2_big.is_err() {
                return Err((422,format!("\nError CPLR95: This is probably due to bad input, but it could be an issue on our end. Make sure the keys are exactly how they are outputted with JUCE, or you can use the defaults by leaving the JUCE Keys empty. More: {:?}", p2_big.unwrap_err())));
            }

            return Ok((
                public_key, 
                format!("{:?},{:?}",
                    general_purpose::STANDARD.encode(
                        p1_big.unwrap().to_bytes_be()
                    ),
                    general_purpose::STANDARD.encode(
                        p2_big.unwrap().to_bytes_le()
                    )
                )
            ));
        }

        // convert key to base64, both keys are Some<String>
        let private_key = private_option.unwrap();
        let comma_opt = private_key.find(',');
        if comma_opt.is_none(){
            return Err((400,"\nError: Invalid JUCE keys, they must be 2048 bit JUCE RSA Keys, or leave empty to use default keys.".to_owned()));
        }
        let comma = comma_opt.unwrap();

        let public_key = public_option.unwrap();
        let comma_pub_opt = public_key.find(',');
        if comma_pub_opt.is_none() {
            return Err((400,"\nError: Invalid JUCE keys, they must be 2048 bit JUCE RSA Keys, or leave empty to use default keys.".to_owned()));
        }
        let comma_pub = comma_pub_opt.unwrap();

        let private_p1 = private_key.substring(0, comma);
        let private_p2 = private_key.substring(comma+1, private_key.len());
        
        let public_p1 = public_key.substring(0, comma_pub);
        let public_p2 = public_key.substring(comma_pub + 1, public_key.len());

        if self.juce_public_full.is_none() {
            self.juce_public_full = Some(public_key.to_owned());
        }

        let p1_big = num_bigint::BigUint::from_str_radix(private_p1, 16);
        let p2_big = num_bigint::BigUint::from_str_radix(private_p2, 16);

        if p1_big.is_err() {
            return Err((422, format!("\nError CPLR132. This is probably due to bad input, but it could be an issue on our end. Make sure the keys are exactly how they are outputted with JUCE, or you can use the defaults by leaving the JUCE Keys empty. More: {:?}", p1_big.unwrap_err())));
        }
        if p2_big.is_err() {
            return Err((422, format!("\nError CPLR135: This is probably due to bad input, but it could be an issue on our end. Make sure the keys are exactly how they are outputted with JUCE, or you can use the defaults by leaving the JUCE Keys empty. More: {:?}", p2_big.unwrap_err())));
        }
        // check key size
        if !private_p1.len_between(500, 514) {
            return Err((400, "\nError CPLR229: private key must be 2048 bits, exactly as JUCE displays with toString()".to_owned()));
        } 
        if !private_p2.len_between(500, 514) {
            return Err((400, "\nError CPLR232: private key must be 2048 bits, exactly as JUCE displays with toString()".to_owned()));
        }
        if !public_p2.len_between(500, 514) {
            return Err((400, "Error CPLR235: public key must be 2048 bits, exactly as JUCE displays with toString().".to_owned()));
        }
        if public_p1.len() > 5 {
            return Err((400, format!("\nError CPLR238: Keys must be 2048 bits, exactly as JUCE displays with toString()")));
        }
        if !public_p2.eq_ignore_ascii_case(private_p2) {
            return Err((400, "\nError CPLR141: Keys must be valid.".to_string()));
        }

        return Ok((
            public_p1.to_string(),
            format!("{},{}",
                general_purpose::STANDARD.encode(
                    p1_big.unwrap().to_bytes_be()
                ),
                general_purpose::STANDARD.encode(
                    p2_big.unwrap().to_bytes_le()
                ))
        ));
    }

    /**
     * Generates a hashmap for the database
     */
    pub fn get_hashmap(&self) -> Result<HashMap<String, AttributeValue>, HttpError> {
        let mut map: HashMap<String, AttributeValue> = HashMap::new();
        map.insert_data("version", &self.version, S);
        map.insert_data("Calls", "0", N);
        map.insert_bool("isOfflineEnabled", self.is_offline_enabled);
        map.insert_bool("isOnlineEnabled", self.is_online_enabled);
        map.insert_data("MaxMachinesPerLicense", &self.machine_limit, N);
        if self.juce_private_key.is_none() {
            return Err("Error CPLR268q".into());
        }
        if self.juce_public_key.is_none() {
            return Err("Error CPLR271p".into());
        }
        map.insert_data("PrivateKeyJUCE", &self.juce_private_key.as_ref().unwrap(), S);
        map.insert_data("PublicKeyJUCE", &self.juce_public_key.as_ref().unwrap(), S);

        // insert language stuff, loop over languages
        map.insert_language_support(&self.language_support);

        // insert license type stuff, loop over license types
        map.insert_license_info(&self.enabled_license_types);

        return Ok(map.to_owned());
    }

    pub fn get_license_types(&self) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        for license_type in self.enabled_license_types.iter() {
            result.push(license_type.type_name.to_owned());
        }
        return result;
    }

    pub fn get_languages(&self) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();
        for lang in self.language_support.iter() {
            result.push(lang.language_name.to_owned());
        }
        return result;
    }

}

#[derive(Serialize, Deserialize, Debug)]
pub struct LanguageSupport {
    language_name: String,
    license_no_longer_active: String,
    incorrect_offline_code: Option<String>,
    no_license_found: String,
    over_max_machines: String,
    success: String,
    //temp_license_ended: String,
}
impl LanguageSupport {
    fn validate(&self) -> Result<(), String> {
        let mut error = "".to_owned();
        if self.language_name.len() > 16 {
            error.push_str("\nError: language_name must be less than 16 characters long.");
        }
        if self.incorrect_offline_code.is_some() {
            if self.incorrect_offline_code.as_ref().unwrap().len() > 140 {
                error.push_str("\nError: incorrect_offline_code response must be under 140 characters or left blank.");
            }
        }
        if self.no_license_found.len() > 140 {
            error.push_str("\nError: no_license_found response must be under 140 characters.");
        }
        if self.over_max_machines.len() > 140 {
            error.push_str("\nError: over_max_machines message must be less than 140 characters.");
        }
        if self.success.len() > 1000 {
            error.push_str("\nError: Success message must be less than 1000 characters.");
        }
        if self.license_no_longer_active.len() > 140 {
            error.push_str("\nError: license_no_longer_active response must be less than 140 characters.");
        }
        if error.len() > 1 {
            return Err(error);
        }
        return Ok(());
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LicenseType {
    type_name: String,
    expiration_days: Option<u16>,
    frequency_days: Option<f32>,
    expiration_leniency: Option<u8>,
    frequency_hours: Option<String>
}
impl LicenseType {
    pub fn capitalize(&mut self) -> String {
        let lower = self.type_name.to_lowercase();
        let mut chars = lower.chars();
        match chars.next() {
            None => {return "".to_owned();},
            Some(first) => {
                let first_upper = first.to_uppercase().collect::<String>();
                return format!("{}{}", &first_upper, chars.as_str());
            }
        }
    }
    pub fn validate(&mut self) -> Result<(), String> {
        let mut error = "Error: ".to_owned();
        let license_types_vec = vec!["beta", "offline", "online", "trial", "subscription", "lax"];
        if self.frequency_days.is_some() {
            let f = self.frequency_days.as_ref().unwrap();
            self.frequency_hours = Some((f * 24 as f32).to_string());
        }
        if !license_types_vec.contains(&self.type_name.to_ascii_lowercase().as_str()) {
            error.push_str(&format!("\n{:?} license type doesn't exist as a possible license type.", &self.type_name));
        }
        if !&self.type_name.eq_ignore_ascii_case("lax"){
            if self.frequency_hours.is_none() {
                error.push_str(&format!("\n{:?} license type needs frequency_hours parameter set. ", &self.type_name));
            }
            if !self.type_name.eq_ignore_ascii_case("offline"){
                if (&self).expiration_days.is_none(){
                    error.push_str(&format!("\n{:?} license type needs expiration_days parameter set. ", &self.type_name));
                }
            }
            if self.expiration_leniency.is_some() && self.type_name.eq_ignore_ascii_case("subscription") {
                // let leniency = self.expiration_leniency.to_owned().unwrap();
            }
        }

        let expiration_outer: Option<f32>;
        // check that the options can be parsed as ints and floats
        if self.expiration_days.is_some() {
            let expiration = self.expiration_days.as_ref().unwrap().to_owned();
            if &expiration < &1 || &expiration > &9001 {
                error.push_str(&format!("\n{:?}_expiration_days value needs to be between 1 and 9001", &self.type_name));
            }
            expiration_outer = Some(expiration as f32);
        }else{
            expiration_outer = None;
        }

        if self.frequency_hours.is_some() {
            let test_frequency_float_result: Result<f32, ParseFloatError> = self.frequency_hours.to_owned().unwrap().parse();
            if test_frequency_float_result.is_err() {
                error.push_str(&format!("\n{:?}_frequency_hours value needs to be between 0.5 and 1000", &self.type_name));
            }else{
                let frequency = test_frequency_float_result.unwrap();
                if &frequency < &0.5 || &frequency > &(24000 as f32) {
                    error.push_str(&format!("\n{:?}_frequency_hours value needs to be between 0.5 and 1000", &self.type_name));
                }
                if expiration_outer.is_some() {
                    let expiration = expiration_outer.unwrap();
                    if &expiration * (24 as f32) < frequency {
                        error.push_str(&format!("\nFrequency must be less than the time it takes for the license to expire, so for your given expiration_days of {:?}, the maximum frequency should be less than {:?}",
                            &expiration, &expiration * (24 as f32)));
                    }
                }
            }
        }


        if error.len() > 10 {
            return Err(error.to_owned());
        }
        return Ok(());
    }
}

trait MapBinding {
    fn insert_license_info(&mut self, license_types: &Vec<LicenseType>);
    fn insert_language_support(&mut self, languages: &Vec<LanguageSupport>);
}
impl MapBinding for HashMap<String, AttributeValue> {
    /**
     * Inserts all license info from a vector of LicenseType objects into a hashmap
     */
    fn insert_license_info(&mut self, license_types: &Vec<LicenseType>) {
        for license_type in license_types {
            if license_type.expiration_days.is_some() {
                self.insert_data(
                    &format!("{}PolicyExpirationDays", &license_type.type_name), 
                    &license_type.expiration_days.as_ref().unwrap().to_string(), 
                    N
                );
            }
            if license_type.frequency_hours.is_some() {
                self.insert_data(
                    &format!("{}PolicyFrequencyHours", &license_type.type_name),
                    &license_type.frequency_hours.as_ref().unwrap(),
                    N
                );
            }
            if license_type.type_name.eq_ignore_ascii_case("subscription") {
                let leniency: String;
                if license_type.expiration_leniency.is_some() {
                    leniency = license_type.expiration_leniency.unwrap().to_string();
                }else{
                    leniency = "0".to_owned();
                }
                self.insert_data(
                    &format!("{}ExpirationLeniency", &license_type.type_name),
                    &leniency,
                    N
                );
            }
        }
    }

    /**
     * Inserts language info from a vector of LanguageSupport objects into a hashmap
     */
    fn insert_language_support(&mut self, languages: &Vec<LanguageSupport>) {
        let mut lang_support_map: HashMap<String, AttributeValue> = HashMap::new();
        for lang in languages {
            /*
            self.insert_data(
                &format!("{}IncorrectOfflineCode", &lang.language_name),
                &lang.incorrect_offline_code,
                S
            );
            self.insert_data(
                &format!("{}LicenseNoLongerActive", &lang.language_name),
                &lang.license_no_longer_active,
                S
            );
            */

            let lang_map: HashMap<String, AttributeValue> = HashMap::new()
                .insert_strings(vec![
                    ("NoLicenseFound", &lang.no_license_found),
                    ("OverMaxMachines", &lang.over_max_machines),
                    ("Success", &lang.success),
                    ("LicenseNoLongerActive", &lang.license_no_longer_active)
            ]);
            lang_support_map.insert_map(&lang.language_name, Some(lang_map));
        }
        self.insert_map("language_support", Some(lang_support_map));
    }
}