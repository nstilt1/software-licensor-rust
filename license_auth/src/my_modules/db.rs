use rusoto_dynamodb::{DynamoDbClient, DynamoDb, AttributeValue};
use std::collections::HashMap;
use lambda_http::{Response, Error};

use crate::my_modules::juce::{auto_response, success};

static PLUGINS_TABLE_NAME: &str = "Plugins";
static MACHINES_TABLE_NAME: &str = "Machines";

/**
 * Returns the machine data that the user can see through the website.
 * .0 = whether the data needs to be updated in the database
 * .1 = the new hashmap of the machines for the license
 */
pub fn update_user_license_method(
    license_map: HashMap<String, AttributeValue>,
    mach: String,
    os: String,
    computer_name: String
) -> Result<(bool, Option<HashMap<String, AttributeValue>>), String> {
    let machines_opt = license_map.get("machines");
    if machines_opt.is_none() {
        return Err("Error DU18".to_owned());
    }
    let machines_attr = machines_opt.unwrap().m.as_ref();
    if machines_attr.is_none() {
        return Err("Error DU22".to_owned());
    }
    let mut machines_map = machines_attr.unwrap().to_owned();
    if machines_map.contains_key(&mach) {
        let machine_item_opt = machines_map.get(&mach).unwrap().m.as_ref();
        if machine_item_opt.is_none() {
            return Err("Error DU28".to_owned());
        }
        let machine_item = machine_item_opt.unwrap().to_owned();
        let found_os = machine_item.get("os").unwrap().s.as_ref().unwrap().to_owned();
        let found_c_name = machine_item.get("computer_name").unwrap().s.as_ref().unwrap().to_owned();
        // the values match, no changes needed
        if &found_os == &os && &found_c_name == &computer_name {
            return Ok((false, None));
        }
    }
    // create a map for the machine, then put it in the machines_map
    let mut new_machine_map: HashMap<String, AttributeValue> = HashMap::new();
    new_machine_map.insert(
        "os".to_owned(),
        AttributeValue {
            s: Some(os.to_owned()),
            ..Default::default()
        }
    );
    new_machine_map.insert(
        "computer_name".to_owned(),
        AttributeValue {
            s: Some(computer_name.to_owned()),
            ..Default::default()
        }
    );

    machines_map.insert(
        mach.to_owned(),
        AttributeValue {
            m: Some(new_machine_map.to_owned()),
            ..Default::default()
        }
    );

    return Ok((true, Some(machines_map.to_owned())));
}

pub fn create_mach(company: &str, plugin: &str, mach: &str, cpu_stats: Vec<(String, String)>, instructions: Vec<(String, String)>) -> rusoto_dynamodb::TransactWriteItem {
    let mut result_item_map: HashMap<String, AttributeValue> = HashMap::new();

    result_item_map.insert("id".to_owned(), AttributeValue {
        s: Some(mach.to_owned()),
        ..Default::default()
    });

    // add remaining stats and instructs
    let mut instructs_map: HashMap<String,AttributeValue> = HashMap::new();
    for inst in instructions {
        instructs_map.insert(
            inst.0.to_owned(),
            AttributeValue {
                s: Some(inst.1.to_owned()),
                ..Default::default()
            }
        );
    }
    let mut stats_map: HashMap<String, AttributeValue> = HashMap::new();
    for st in cpu_stats {
        stats_map.insert(
            st.0.to_owned(),
            AttributeValue {
                s: Some(st.1.to_owned()),
                ..Default::default()
            }
        );
    }
    result_item_map.insert(
        "Instructions".to_owned(),
        AttributeValue {
            m: Some(instructs_map.to_owned()),
            ..Default::default()
        }
    );
    result_item_map.insert(
        "Stats".to_owned(),
        AttributeValue {
            m: Some(stats_map.to_owned()),
            ..Default::default()
        }
    );

    let mut company_map: HashMap<String, AttributeValue> = HashMap::new();
    company_map.insert(
        company.to_owned(),
        AttributeValue {
            ss: Some(vec![plugin.to_owned()]),
            ..Default::default()
        }
    );
    result_item_map.insert(
        "CompanyIDs".to_owned(),
        AttributeValue {
            m: Some(company_map.to_owned()),
            ..Default::default()
        }
    );

    return rusoto_dynamodb::TransactWriteItem {
        put: Some(rusoto_dynamodb::Put {
            item: result_item_map.to_owned(),
            table_name: MACHINES_TABLE_NAME.to_owned(),
            ..Default::default()
        }),
        ..Default::default()
    };
}

pub fn check_stats<'a>(
    company_id: &str, 
    plugin_id: &str, 
    mach: &str, 
    cpu_stats: &mut Vec<(String, String)>, 
    instructions: &mut Vec<(String, String)>, 
    machine_list_item: &mut HashMap<String, AttributeValue>) -> Result<Option<rusoto_dynamodb::Update>, &'a str> {
    let mut changed = false;

    /*
    for ins in &instructions {
        if !ins.compare(machine_list_item){
            changed = true;
        }
    }
    */
    //return Err("735");
    let mut i = 0;
    while i < instructions.len() {
        if !check_stat(instructions.get_mut(i).unwrap(), machine_list_item) {
            changed = true;
        }
        i += 1;
    }
    i = 0;
    while i < cpu_stats.len() {
        if !check_stat(cpu_stats.get_mut(i).unwrap(), machine_list_item) {
            changed = true;
        }
        i += 1;
    }
    /*
    for stat in &cpu_stats {
        if !stat.compare(machine_list_item){
            changed = true;
        }
    }
    */
    //return Err("756");
    if !changed {
        return Ok(None);
    }else{
        let mut update_expr = vec!["#a = :a".to_owned(), "#b = :b".to_owned()];
        let mut expr_attr_names: HashMap<String, String> = HashMap::new();
        expr_attr_names.insert(
            "#a".to_owned(), 
            "Instructions".to_owned()
        );
        let mut expr_attr_vals: HashMap<String, AttributeValue> = HashMap::new();
        
        let mut instructions_hashmap: HashMap<String, AttributeValue> = HashMap::new();
        for inst in instructions {
            instructions_hashmap.insert(
                inst.0.to_owned(),
                AttributeValue {
                    s: Some(inst.1.to_owned()),
                    ..Default::default()
                }
            );
        }
        expr_attr_vals.insert(
            ":a".to_owned(),
            AttributeValue {
                m: Some(instructions_hashmap.to_owned()),
                ..Default::default()
            }
        );

        expr_attr_names.insert(
            "#b".to_owned(),
            "Stats".to_owned()
        );

        let mut stats_hashmap: HashMap<String, AttributeValue> = HashMap::new();
        for stat in cpu_stats {
            stats_hashmap.insert(
                stat.0.to_owned(),
                AttributeValue {
                    s: Some(stat.1.to_owned()),
                    ..Default::default()
                }
            );
        }
        expr_attr_vals.insert(
            ":b".to_owned(),
            AttributeValue {
                m: Some(stats_hashmap.to_owned()),
                ..Default::default()
            }
        );
        // do the same for cpu_stats
        let instructs_map = AttributeValue {
            m: Some(instructions_hashmap.to_owned()),
            ..Default::default()
        };
        expr_attr_vals.insert(
            ":a".to_owned(),
            instructs_map.to_owned()
        );

        let mut mach_key: HashMap<String, AttributeValue> = HashMap::new();
        mach_key.insert(
            "id".to_owned(),
            AttributeValue {
                s: Some(mach.to_owned()),
                ..Default::default()
            }
        );
    ///////////////////
        //return Err("826");
        let mut old_company_map_exists = !machine_list_item.is_empty();
        if old_company_map_exists {
            old_company_map_exists = machine_list_item.contains_key("CompanyIDs");
        }

        if old_company_map_exists {
            let mut old_company_map = machine_list_item.get_mut("CompanyIDs").unwrap().m.as_ref().unwrap().to_owned();
            let company_exists_in_map = old_company_map.contains_key(company_id);
            let plugin_exists_in_map: bool;
            /*
            let plugin_list_item = AttributeValue {
                s: Some(plugin_id.to_owned()),
                ..Default::default()
            };
            */


            if company_exists_in_map {
                //return Err("839");
                plugin_exists_in_map = old_company_map.get(company_id).unwrap().ss.as_ref().unwrap().contains(&plugin_id.to_owned());
                if !plugin_exists_in_map {
                    update_expr.push("#c = :c".to_owned());
                    expr_attr_names.insert(
                        "#c".to_owned(),
                        "CompanyIDs".to_owned()
                    );
                    let mut new_company_map: HashMap<String, AttributeValue> = HashMap::new();

                    let mut new_company_list = old_company_map.get_mut(company_id).unwrap().ss.as_ref().unwrap().to_owned();
                    new_company_list.push(plugin_id.to_string());
                    new_company_map = old_company_map.clone();
                    new_company_map.remove(company_id);
                    new_company_map.insert(company_id.to_owned(), AttributeValue {
                        ss: Some(new_company_list.to_owned()),
                        ..Default::default()
                    });
                    //company_map.get_mut(company_id).unwrap().ss.as_ref().unwrap().push(plugin_id.to_string());
                    expr_attr_vals.insert(
                        ":c".to_owned(),
                        AttributeValue {
                            m: Some(new_company_map.to_owned()),
                            ..Default::default()
                        }
                    );
                }
            }else{
                //return Err("866");
                // company does not exist in map
                update_expr.push("#c = :c".to_owned());
                expr_attr_names.insert(
                    "#c".to_owned(),
                    "CompanyIDs".to_owned()
                );
                let new_company_attr = AttributeValue {
                    ss: Some(vec![plugin_id.to_owned()]),
                    ..Default::default()
                };
                old_company_map.insert(
                    company_id.to_owned(),
                    new_company_attr.to_owned()
                );
                expr_attr_vals.insert(
                    ":c".to_owned(),
                    AttributeValue {
                        m: Some(old_company_map.to_owned()),
                        ..Default::default()
                    }
                );
            }
        }else {
            // company map does not exist
            return Err("Company not found.");
        }
        

        return Ok(Some(rusoto_dynamodb::Update {
            update_expression: format!("SET {}", update_expr.join(",").to_owned()),
            expression_attribute_names: Some(expr_attr_names.to_owned()),
            expression_attribute_values: Some(expr_attr_vals.to_owned()),
            key: mach_key.to_owned(),
            table_name: MACHINES_TABLE_NAME.to_owned(),
            ..Default::default()
        }));
    }
}

pub fn check_stat(pair: &mut (String, String), original: &mut HashMap<String, AttributeValue>) -> bool {
    
    // catch the errors
    if original.is_empty() {
        return false;
    }
    if !original.contains_key("Stats") {
        return false;
    }
    if !original.contains_key("Instructions") {
        return false;
    }
    let which = if original.get("Stats").unwrap().m.as_ref().unwrap().contains_key(&pair.0) { "Stats"} else { "Instructions" };
    let map = original.get(which).unwrap().m.as_ref();
    if map.is_none() {
        return false;
    }
    let attr = map.unwrap().get(&pair.1);
    if attr.is_none() {
        return false;
    }
    let str = attr.unwrap().s.as_ref();
    if str.is_none() {
        return false;
    }


    // actual analysis
    let og = str.unwrap().to_owned();
    if &og == &pair.1 {
        return true;
    }
    if &pair.1.len() == &(0 as usize) || &pair.1.to_ascii_lowercase() == "x" {
        pair.1 = og.to_string();
        return true;
    }
    return false;
}
pub async fn increment_plugin_calls_slow(client: DynamoDbClient, plugins_key_map: HashMap<String, AttributeValue>) {
    let mut plug_update_names: HashMap<String, String> = HashMap::new();
    plug_update_names.insert("#a".to_owned(), "Calls".to_owned());
    let mut plug_update_vals: HashMap<String, AttributeValue> = HashMap::new();
    plug_update_vals.insert(":a".to_owned(),
        AttributeValue {
            n: Some(1.to_string()),
            ..Default::default()
    });

    
    let _plugin_output = client.update_item(
        rusoto_dynamodb::UpdateItemInput {
            update_expression: Some("ADD #a :a".to_owned()),
            key: plugins_key_map.to_owned(),
            table_name: PLUGINS_TABLE_NAME.to_owned(),
            expression_attribute_names: Some(plug_update_names.to_owned()),
            expression_attribute_values: Some(plug_update_vals.to_owned()),
            ..Default::default()
        }
    ).await;
}


pub async fn transact_write(
    client: DynamoDbClient,
    transact_items_og: Vec<rusoto_dynamodb::TransactWriteItem>, 
    company: &str,
    messages_vec: Option<Vec<String>>,
    messages_enabled: bool,
    messages_frequency: Option<String>,
    plugin: &str,
    mach: &str,
    cpu_stats: &mut Vec<(String, String)>,
    instructions: &mut Vec<(String, String)>,
    machine_list_item: &mut HashMap<String, AttributeValue>,
    license_code: &str,
    language_support: HashMap<String, AttributeValue>,
    plugin_item: &HashMap<String, AttributeValue, std::collections::hash_map::RandomState>,
    license_data: &HashMap<String, AttributeValue, std::collections::hash_map::RandomState>,
    license_type: &str,
    machines_allowed: usize,
    initial_total_machines: usize,
    is_offline_license: bool,
    message: &&AttributeValue,
    machine_exists: bool,
    new_expiry: Option<i64>
) -> Result<Response<String>, Error>{
    let machine_item: Option<rusoto_dynamodb::Update>;
    let mut transact_items = transact_items_og.to_owned();


    if machine_exists {
        let machine_item_test = check_stats(&company, &plugin, &mach, cpu_stats, instructions, &mut machine_list_item.to_owned());
        if machine_item_test.is_err() {
            return auto_response(true, 500, machine_item_test.err().unwrap());
        }
        machine_item = machine_item_test.unwrap();
        if machine_item.is_some() {
            transact_items.push(
                rusoto_dynamodb::TransactWriteItem{
                    update: Some(machine_item.unwrap()),
                    ..Default::default()
                }
            );

            match client.transact_write_items(
                rusoto_dynamodb::TransactWriteItemsInput {
                    transact_items: transact_items,
                    ..Default::default()
                }
            ).await {
                Ok(_x) => {
                    return success(&plugin, messages_vec.to_owned(), messages_enabled.to_owned(), messages_frequency.to_owned(), &message, is_offline_license, initial_total_machines, machines_allowed, &license_type, license_data, plugin_item, language_support, &mach, &license_code, new_expiry);
                },
                Err(x) => {
                    return auto_response(true, 500, &format!("Internal Error: TW-DB1, {:?}", x.to_string()));
                }
            };
        }else{
            // machine exists already and no
            // changes are necessary
            match client.transact_write_items(
                rusoto_dynamodb::TransactWriteItemsInput {
                    transact_items: transact_items,
                    ..Default::default()
                }
            ).await {
                Ok(_x) => {
                    return success(&plugin, messages_vec.to_owned(), messages_enabled.to_owned(), messages_frequency.to_owned(), &message, is_offline_license, initial_total_machines, machines_allowed, &license_type, license_data, plugin_item, language_support, &mach, &license_code, None);

                },
                Err(x) => {
                    return auto_response(true, 500, &format!("Internal Error: TW-DB1, {:?}", x.to_string()));
                }
            }
        }
    }
    // return statements are above

    // machine does not exist

    let new_mach = create_mach(&company, &plugin, &mach, cpu_stats.to_vec(), instructions.to_vec());
    transact_items.push(
        new_mach.to_owned()
    );


    match client.transact_write_items(
        rusoto_dynamodb::TransactWriteItemsInput {
            transact_items: transact_items.to_owned(),
            ..Default::default()
        }
    ).await {
        Ok(_x) => {
            return success(&plugin, messages_vec.to_owned(), messages_enabled.to_owned(), messages_frequency.to_owned(), &message, is_offline_license, initial_total_machines, machines_allowed, &license_type, license_data, plugin_item, language_support, &mach, &license_code, new_expiry);
        },
        Err(x) => {
            return auto_response(true, 500, &format!("Internal Error: TW-DB1, {:?}", x.to_string()));
        }
    }
}