use substring::Substring;
use std::collections::HashMap;
use rusoto_dynamodb::AttributeValue;

pub fn parse_bool(input: &str) -> bool {
    return match input.to_ascii_lowercase().as_ref() {
        "true" => true,
        "false" => false,
        "0" => false,
        "1" => true,
        "t" => true,
        "f" => false,
        _ => false
    }
}

pub fn cleanse (text: &str, extra_chars: &str) -> String {
    let mut allowed_chars = "ASDFGHJKLQWERTYUIOPZXCVBNM1234567890".to_owned();
    allowed_chars.push_str(extra_chars);
    let mut output = "".to_owned();
    for ch in text.chars() {
        let upper = ch.to_ascii_uppercase();
        if allowed_chars.contains(upper){
            output.push(upper);
        }
    }
    output.to_owned()
}

/**
 * This was a function that checked to see if a private 4-digit code matched what 
 * we have. This was going to be used because Offline licenses couldn't determine 
 * whether a machine has stopped using its licensed software after the machine 
 * was 'removed' from the license, so if someone gave away their license code, 
 * they might permanently not be able to add any more machines to the license. 
 * 
 * This is now obsolete, as I have chosen the simpler approach of assuming that 
 * the users won't abuse this. For them to abuse it, they would need to find 
 * a way to prevent the software from contacting our server, then free the machine 
 * from the license.
 * 
 * People would think the other solution was weird.
 */
pub fn perm_codes_equal(given: &str, official: &str, license_type: &str) -> Result<bool, String> {
    return Ok(true);
    // permanent
    if given.substring(0,9).eq_ignore_ascii_case("OFFLINE") {
        if official.eq_ignore_ascii_case(given.substring(given.len()-5, given.len())) {
            if !license_type.eq_ignore_ascii_case("trial") && !license_type.eq_ignore_ascii_case("subscription") && !license_type.eq_ignore_ascii_case("beta") {
                return Ok(true);
            }
            return Err("NoLicenseFound".to_owned());
        }
    }
    return Err("IncorrectOfflineCode".to_owned());
}

/**
 * Modify the plugin license data hashmap, then return it as
 * an attribute expression value to be sent to the database
 */
pub fn modify_hashmap (
    entire: &HashMap<String, AttributeValue>, 
    individual: &HashMap<String, AttributeValue>, 
    plugin: &str, 
    online_machines_op: Option<&Vec<AttributeValue>>, 
    offline_machines_op: Option<&Vec<AttributeValue>>,
    activation_time_op: Option<String>,
    expiry_time_op: Option<String>) 
    -> Result<HashMap<String, AttributeValue>, String> {
    let mut plugin_license_data = individual.clone();
    if online_machines_op.is_some() {
        plugin_license_data.entry("Online".to_owned())
            .and_modify(
                |e| { 
                    *e = AttributeValue {
                        l: Some(online_machines_op.unwrap().to_owned()),
                        ..Default::default()
                    }
                }
        );
    }
    if offline_machines_op.is_some() {
        plugin_license_data.entry("Offline".to_owned())
            .and_modify(|e| {
                *e = AttributeValue {
                    l: Some(offline_machines_op.unwrap().to_owned()),
                    ..Default::default()
                }
            }
        );
    }
    if activation_time_op.is_some() {
        plugin_license_data.entry("ActivationTime".to_owned())
            .and_modify(|e| {
                *e = AttributeValue {
                    s: Some(activation_time_op.unwrap().to_string()),
                    ..Default::default()
                }
            });
    }
    if expiry_time_op.is_some() {
        plugin_license_data.entry("ExpiryTime".to_owned())
            .and_modify(|e| {
                *e = AttributeValue {
                    s: Some(expiry_time_op.unwrap().to_string()),
                    ..Default::default()
                }
            });
    }
    let all_license_data = entire.clone();
    let plugins_map_option = all_license_data.get("Plugins");
    if plugins_map_option.is_none() {
        return Err("Error AJ1211".to_owned());
    }
    let mut plugins_map = plugins_map_option.unwrap().m.as_ref().unwrap().to_owned();
    plugins_map.entry(plugin.to_owned())
        .and_modify(|e| {
            *e = AttributeValue {
                m: Some(plugin_license_data.to_owned()),
                ..Default::default()
            }
        });

    let mut result: HashMap<String, AttributeValue> = HashMap::new();
    result.insert(
        ":a".to_owned(),
        AttributeValue {
            m: Some(plugins_map.to_owned()),
            ..Default::default()
        }
    );

    return Ok(result.to_owned());
}