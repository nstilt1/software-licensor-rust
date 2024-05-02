use base64::{engine::general_purpose, Engine as _};
use lambda_http::{Error, Response};
use num_bigint::BigUint;
use rand::prelude::*;
use std::collections::HashMap;
use rusoto_dynamodb::AttributeValue;

use num_traits::{Zero, Num};
use substring::Substring;

use std::time::{SystemTime, UNIX_EPOCH};
use chrono::prelude::{Utc, TimeZone, Datelike, Timelike};
use std::ops::{AddAssign, MulAssign};
use num_integer::Integer;

//use num_traits::Zero;

// builds and returns a response in JUCE's format
pub fn auto_response(is_error: bool, status: u16, response_text: &str) -> Result<Response<String>, Error> {
    let mut resp: Response<String> = Response::builder()
        .status(status)
        .header("content-type", "text/xml")
        .header("charset", "utf-8")
        .body(r#"<?xml version="1.0" encoding="utf-8"?>"#.into())
        .map_err(Box::new)?;    //let lowercase = response_text.to_ascii_lowercase();
    if is_error {
        resp.body_mut().push_str(r#"<ERROR error=""#);
        let removed: String = response_text.chars()
            .map(|x| match x {
                '"' => '\'',
                _ => x }).collect();
            
        resp.body_mut().push_str(&removed);
        resp.body_mut().push_str(r#""></ERROR>"#);
    }else{
        resp.body_mut().push_str("<MESSAGE message=\"");
        resp.body_mut().push_str(response_text);
    }
    return Ok(resp);
}

/**
 * Format the encrypted key
 */
pub fn encrypt_format(value: BigUint, pretty_print: bool) -> String {
    if pretty_print {
        let mut result = "".to_owned();
        let mut as_hex = "#".to_owned();
        as_hex.push_str(&value.to_str_radix(16));
        //println!("As Hex = {:?}", as_hex);
        let mut iterator = 0;
        let len = as_hex.chars().count();
        as_hex.push_str(&value.to_str_radix(16));
        loop {
            let diff = len - iterator;
            if diff <= 0 {
                break;
            }
            let min = if 70 < diff { 70 } else { diff };
            result.push_str(&as_hex.substring(iterator, min + iterator));
            result.push('\n');
            iterator += min;
            //println!("Iterator = {:?}", iterator);
            //println!("min = {:?}", min);
            //as_hex = as_hex.substring(70, len).to_owned();
        }
        return result;
    }else{
        let mut result = "#".to_owned();
        result.push_str(&value.to_str_radix(16));
        return result;
    }
}

/**
 * Apply key to value
 */
pub fn apply_to_value (value: BigUint, key: &str) -> BigUint {
    //println!("{}", key.contains(','));
    let split_key = (key).split(',').collect::<Vec<&str>>();
    let mut val = value;
    let mut result = BigUint::zero();
    //println!("{:?}", split_key);
    let p1 = BigUint::from_str_radix(&split_key[0], 36).unwrap();
    let p2 = BigUint::from_str_radix(&split_key[1], 36).unwrap();

    if p1.is_zero() || p2.is_zero() || val <= Zero::zero(){
        return result.to_owned();
    }
    
    while !val.is_zero() {
        result.mul_assign(&p2);
        //let mut div = div_rem(val.to_owned(), p2.to_owned());
        let div = val.div_rem(&p2);
        val = div.0;
        result.add_assign(div.1.modpow(&p1, &p2));
        //println!("val = {:?}", val.to_string());
        //println!("div.1 = {:?}", div.1.to_string());
    }

    //println!("Result = {:?}", result.to_str_radix(16));

    return result;
}

/**
 * Build the XML data.
 */
pub fn build_xml (
    username: &str, 
    version: &str,
    messages_vec: Option<Vec<String>>,
    messages_enabled: bool,
    messages_frequency: Option<String>,
    order: &str, 
    machine_numbers: &str,
    app_name: &str,
    license_code: &str,
    license_type: &str,
    machine_attribute: &str,
    timestamp: std::time::Duration,
    expiration_addition: Option<i64>,
    frequency_addition: Option<i64>) -> BigUint 
{
    let mut xml: String = r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_owned();
    xml.push_str(r#"<key user=""#);
    xml.push_str(&username);
    xml.push_str(r#"" order=""#);
    xml.push_str(&order);
    xml.push_str(r#"" "#);
    xml.push_str(r#" license=""#);
    xml.push_str(&license_code);
    xml.push_str(r#"" "#);
    xml.push_str(r#" email=""#);
    xml.push_str(&license_code);
    xml.push_str(r#"" "#);
    xml.push_str(&machine_attribute);
    xml.push_str(r#"=""#);
    xml.push_str(&machine_numbers);
    xml.push_str(r#"" app=""#);
    xml.push_str(&app_name);
    xml.push_str(r#"" licenseType=""#);
    xml.push_str(&license_type);

    xml.push_str(r#"" version=""#);
    xml.push_str(&version);
    
    if messages_enabled && messages_vec.is_some() && messages_frequency.is_some() {
        let messages = messages_vec.unwrap();
        let message_freq = messages_frequency.unwrap();
        xml.push_str(r#"" messages=""#);
        xml.push_str(&messages.join("."));
        xml.push_str(r#"" customFreq=""#);
        xml.push_str(&message_freq);
    }

    xml.push_str(r#"" date=""#);
    //let timestamp_millis = timestamp.unwrap().as_millis();
    //println!("time = {:?}", timestamp_millis.to_string());
    //let timestamp_big_int = BigUint::from_bytes_le(&timestamp_millis.to_le_bytes());
    //let timestamp_byte_str = timestamp_big_int.to_str_radix(16);
    //println!("time in bytes = {:?}", timestamp_byte_str);

    // this one is used in the following xml.push_str
    //let condensed_time_str = BigUint::from_bytes_le(&timestamp_millis.to_le_bytes()).to_str_radix(16);
    //println!("Condensed time string = {:?}", condensed_time_str);
    let timestamp_millis = timestamp.to_owned().as_millis();
    xml.push_str(&BigUint::from_bytes_le(&timestamp_millis.to_le_bytes()).to_str_radix(16));
    xml.push_str(r#"""#);
    if &machine_attribute == &"expiring_mach" {
        xml.push_str(r#" expiryTime=""#);
        match expiration_addition {
            Some(x) => {
                xml.push_str(&BigUint::from_bytes_le(&(timestamp_millis + (x as u128 * 1000)).to_le_bytes()).to_str_radix(16));
                xml.push_str(r#"""#);
            },
            None => { return BigUint::zero();}
        }
        
    }
    xml.push_str(r#" check=""#);

        // add the time that the next check should occur, in hours
        match frequency_addition {
            Some(x) => {
                xml.push_str(&BigUint::from_bytes_le(&(timestamp_millis + (x as u128 * 1000)).to_le_bytes()).to_str_radix(16));
                xml.push_str(r#"""#);
            },
            None => { return BigUint::zero();}
        }
    xml.push_str("/>");

    return BigUint::from_bytes_le(&xml.as_bytes());
    //return xml;
    //xml.push_str("<key user=\"" + username + "\" email=\"" + email + "\" ");
    //xml += machineAttributeName + "=\"" + machineNumbers + "\" app=\"";
}

pub trait Encryption {
    fn insert_key(&self, 
                    app_id: &str,
                    version: &str,
                    messages_vec: Option<Vec<String>>,
                    messages_enabled: bool,
                    messages_frequency: Option<String>,
                    user: &str, 
                    order: &str, 
                    machine_nums: &str, 
                    license_code: &str,
                    license_type: &str,
                    app_name: &str, 
                    machine_attribute: &str, 
                    expiry_addition: Option<i64>, 
                    frequency_addition: Option<i64>, 
                    key: &str) -> Self;
}
impl Encryption for String {
    fn insert_key(&self, 
                    app_id: &str,
                    version: &str,
                    messages_vec: Option<Vec<String>>,
                    messages_enabled: bool,
                    messages_frequency: Option<String>,
                    user: &str, 
                    order: &str, 
                    machine_nums: &str, 
                    license_code: &str,
                    license_type: &str,
                    app_name: &str, 
                    machine_attribute: &str, 
                    expiry_addition: Option<i64>, 
                    frequency_addition: Option<i64>, 
                    key: &str) -> Self {
        let mut result: String = self.to_owned();
        result.push_str(r#""><KEY>"#);

        result.push_str("Keyfile for ");
        result.push_str(app_name);
        result.push_str("\nVersion: ");
        result.push_str(&version);
        result.push_str("\nUser: ");
        result.push_str(user);
        result.push_str("\nOrder: ");
        result.push_str(order);
        result.push_str("\nMachine numbers: ");
        result.push_str(machine_nums);
        result.push_str("\nCreated: ");
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let test_timestamp: Result<i64, std::num::TryFromIntError> = timestamp.as_secs().try_into();
        if test_timestamp.is_err() {
            return "Error 494".to_owned();
        }
        let date_time = Utc.timestamp(test_timestamp.unwrap(), 0);
        result.push_str(&date_time.day().to_string());
        let months = vec![
                                " Jan ",
                                " Feb ",
                                " Mar ",
                                " Apr ",
                                " May ",
                                " Jun ",
                                " Jul ",
                                " Aug ",
                                " Sep ",
                                " Oct ",
                                " Nov ",
                                " Dec "
        ];
        result.push_str(months[date_time.month0() as usize]);
        result.push_str(&date_time.year().to_string());
        result.push(' ');
        let hour = date_time.hour12();
        result.push_str(&hour.1.to_string());
        result.push(':');
        result.push_str(&date_time.minute().to_string());
        result.push(':');
        result.push_str(&date_time.second().to_string());
        result.push_str(if hour.0 {"am\n\n" } else { "pm\n\n" });
        
        // preventing the client from breaking when decrypting
        result = result.replace('#', "[hashtag]");


        let xml = build_xml(
            user, 
            &version,
            messages_vec.to_owned(),
            messages_enabled.to_owned(),
            messages_frequency.to_owned(),
            order, 
            machine_nums, 
            app_id, 
            license_code,
            license_type,
            machine_attribute, 
            timestamp,
            expiry_addition,
            frequency_addition    
        );

        // success this far
        //return "made it to 538".to_owned();
        //println!("XML = \n{:?}", xml);

        // encrypt with pretty print encryption
        //result.push_str(&encrypt_format(apply_to_value(xml, key), Some(5)));
        
        // encrypt with faster encryption
        result.push_str(&encrypt_format(apply_to_value(xml, key), false));
        //return "problum with either encrypt format or apply to value".to_owned();
        
        result.push_str("</KEY></MESSAGE>");
        result
    }
}

/**
 * Return a juce-formatted success response
 */
pub fn success(app_id: &str,
            messages_vec: Option<Vec<String>>,
            messages_enabled: bool,
            messages_frequency: Option<String>,
            message: &AttributeValue, 
            is_offline_license: bool,
            initial_total_machines: usize,
            machines_allowed: usize,
            license_type: &str,
            license_data: &HashMap<String, AttributeValue, std::collections::hash_map::RandomState>,
            plugin_item: &HashMap<String, AttributeValue, std::collections::hash_map::RandomState>,
            language_support: HashMap<String, AttributeValue>,
            mach: &str,
            license_code: &str,
            new_expiry: Option<i64>) -> Result<Response<String>, Error> {
    let first_name = license_data.get("FirstName").unwrap().s.as_ref().unwrap();
    let last_name = license_data.get("LastName").unwrap().s.as_ref().unwrap();
    let resp_messages = message.s.as_ref().unwrap().to_owned();
    let mut resp_message: String;
    
    if resp_messages.find('\n').is_some() {
        let messages = resp_messages.split('\n').collect::<Vec<&str>>();
        let mut rng = rand::thread_rng();
        resp_message = messages[rng.gen_range(0..messages.len())].to_owned();
    }else{
        resp_message = resp_messages.to_owned();
    }
    if resp_message.contains("{first}") {
        resp_message = resp_message.replace("{first}", &first_name);
    }
    if resp_message.contains("{last}") {
        resp_message = resp_message.replace("{last}", &last_name);
    }
    if resp_message.contains("{full}") {
        resp_message = resp_message.replace("{full}", &format!("{} {}", &first_name, &last_name));
    }
    if resp_message.contains("{ratio}") {
        resp_message = resp_message.replace("{ratio}", &format!("{}/{}", &initial_total_machines.to_string(), &machines_allowed.to_string()));
    }

    let version_opt = plugin_item.get("version");
    if version_opt.is_none() {
        return auto_response(true, 500, "Error J325: Version not found.");
    }
    let version_str_opt = version_opt.unwrap().s.as_ref().to_owned();
    if version_str_opt.is_none() {
        return auto_response(true, 500, "Error J329: Version not found.");
    }
    let version = version_str_opt.unwrap().to_owned();

    //// ERROR BELOW HERE

    let expiry_addition: Option<i64>;
    let frequency_addition: Option<i64>;
    let mach_attribute: String;
    if is_offline_license {
        expiry_addition = None;
        mach_attribute = "mach".to_owned();
    }else if license_type.eq_ignore_ascii_case("lax"){
        expiry_addition = None;
        mach_attribute = "mach".to_owned();
    }else{
        mach_attribute = "expiring_mach".to_owned();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        // this is all under if a machine was
        // already there, so the expiration time is already set
        let mut expiry_policy = license_type.to_owned();
        if &expiry_policy == "Trial" || &expiry_policy == "Subscription" || &expiry_policy == "Beta" {
            if new_expiry.is_none() {
                let expiry_time = i64::from_str_radix(&license_data.get("ExpiryTime").unwrap().s.as_ref().unwrap(), 36).unwrap();
                //let activation_time = i64::from_str_radix(&license_data.get("ActivationTime").unwrap().s.as_ref().unwrap(), 36).unwrap();
                
                let expiry_difference = expiry_time - &now;
                let subscription_lenience: i64;
                if &expiry_policy == "Subscription" {
                    // how many days that should be added to the expiration
                    subscription_lenience = plugin_item.get("SubscriptionExpirationLenienceDays").unwrap().n.as_ref().unwrap().parse::<i64>().unwrap();
                }else{
                    subscription_lenience = 0;
                }
                let overall_difference = expiry_difference + (subscription_lenience * 86400);
                if overall_difference > 0 {
                    // time has not expired
                    expiry_policy.push_str("PolicyExpirationDays");
                    expiry_addition = Some(overall_difference.min(plugin_item.get(&expiry_policy).unwrap().n.as_ref().unwrap().parse::<i64>().unwrap() * 86400));
                }else{
                    //let mut no_longer_active = client_language.to_owned();
                    //no_longer_active.push_str("LicenseNoLongerActive");
                    
                    let license_ended = language_support.get("LicenseNoLongerActive").unwrap().s.as_ref().unwrap().to_owned();
                    
                    return auto_response(true, 200, &license_ended);
                }
            }else{
                let subscription_lenience: i64;
                if &expiry_policy == "Subscription" {
                    subscription_lenience = plugin_item.get("SubscriptionExpirationLenienceDays").unwrap().n.as_ref().unwrap().parse::<i64>().unwrap();
                }else{
                    subscription_lenience = 0;
                }
                expiry_addition = Some(new_expiry.unwrap() - now + (subscription_lenience * 86400));

                
            }
        }else{
            if &expiry_policy == "Offline" {
                expiry_addition = None;
            }else{
                expiry_policy.push_str("PolicyExpirationDays");
                expiry_addition = Some(plugin_item.get(&expiry_policy).unwrap().n.as_ref().unwrap().parse::<i64>().unwrap() * 86400);
            }
        }
    }
    let mut frequency_policy = license_type.to_owned();
    frequency_policy.push_str("PolicyFrequencyHours");
    if license_type.eq_ignore_ascii_case("lax") {
        frequency_addition = None;
    }else{
        frequency_addition = Some((plugin_item.get(&frequency_policy).unwrap().n.as_ref().unwrap().parse::<f64>().unwrap() * 3600 as f64) as i64);
    }
    let order_id = license_data.get("OrderID").unwrap().s.as_ref().unwrap().to_owned();
    let name_option = &plugin_item.get("Name");
    if name_option.is_none() {
        return auto_response(true, 500, "Error 641");
    }
    let name_result = name_option.unwrap().s.as_ref();
    if name_result.is_none() {
        return auto_response(true, 500, "Error 645");
    }
    let name = name_result.unwrap().to_owned();

    let private_key_option_1 = &plugin_item.get("PrivateKeyJUCE");
    if private_key_option_1.is_none() {
        return auto_response(true, 500, "Error 651");
    }
    let private_key_option_2 = private_key_option_1.unwrap().s.as_ref();
    if private_key_option_2.is_none() {
        return auto_response(true,500,"Error 655");
    }
    let private_key_encoded = private_key_option_2.unwrap().to_owned();
    let private_key_result = decode_private_key(&private_key_encoded);
    if private_key_result.is_err() {
        return auto_response(true, 500, &private_key_result.unwrap_err());
    }
    let private_key = private_key_result.unwrap();

    return auto_response(false, 200, 
        &resp_message.insert_key(
            app_id,
            &version,
            messages_vec.to_owned(),
            messages_enabled.to_owned(),
            messages_frequency.to_owned(),
            &format!("{}, {}", &last_name, &first_name), // user
            &order_id, // order ID
            &mach, // machine
            &license_code, // license code
            &license_type,
            &name, // app name
            &mach_attribute, // machine attribute eg "expiring_mach"
            expiry_addition, // days to add
            frequency_addition, // hours to add
            &private_key)); // private key
}

/**
 * Decodes a private key stored as base64
 */
fn decode_private_key(encoded: &str) -> Result<String, String> {
    let p1 = encoded.substring(0, encoded.find(',').unwrap());
    let p2 = encoded.substring(encoded.find(',').unwrap() + 1, encoded.len());

    println!("{:?}", encoded);
    let p1_binary_r = general_purpose::STANDARD.decode(p1);
    let p2_binary_r = general_purpose::STANDARD.decode(p2);

    if p1_binary_r.is_err() {
        return Err(format!("Error DPK93: {:?}", p1_binary_r.unwrap_err()));
    }
    if p2_binary_r.is_err() {
        return Err(format!("Error DPK96: {:?}", p2_binary_r.unwrap_err()));
    }

    let p1_bin = p1_binary_r.unwrap();
    let p2_bin = p2_binary_r.unwrap();
    let p1_big = BigUint::from_bytes_be(&p1_bin);
    let p2_big = BigUint::from_bytes_le(&p2_bin);
    return Ok(format!("{},{}", p1_big.to_str_radix(16), p2_big.to_str_radix(16)));
}