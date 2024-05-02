//mod my_crypt;
mod my_modules;
use my_modules::my_crypt::*;
use my_modules::juce::*;
use my_modules::utils::*;
use my_modules::db::*;

use lambda_http::{run, service_fn, Error, Request, RequestExt, Response, aws_lambda_events::query_map::QueryMap};
//use tracing::instrument;
// use lambda_http::http::StatusCode;
//use lambda_runtime::LambdaEvent;
//use serde_json::{json, Value};
use std::{collections::HashMap};
use serde::Deserialize;
//use serde::{Deserialize, Serialize};


use rusoto_core::Region;
use rusoto_dynamodb::{
    AttributeValue,
    DynamoDb, 
    DynamoDbClient, 
    //GetItemInput,
    //UpdateItemInput,
    BatchGetItemInput,
    //TransactWriteItemsInput,
    KeysAndAttributes
};

use num_traits::{ToPrimitive};
use substring::Substring;

use std::time::{SystemTime, UNIX_EPOCH};
//use num_traits::Zero;

use radix_fmt::radix_36;



static LICENSE_TABLE_NAME: &str = "Licenses";
static PLUGINS_TABLE_NAME: &str = "Plugins";
static MACHINES_TABLE_NAME: &str = "Machines";
static USERS_TABLE_NAME: &str = "PluginUsers";
static MESSAGES_TABLE_NAME: &str = "Messages";

//static CLIENT: DynamoDbClient = DynamoDbClient::new(Region::UsEast2);

//static mut PLUGINS_MAP: HashMap<String, AttributeValue> = HashMap::new();

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct MyRequest {
    company: String,
    product: String,
    license_code: String,
    personalized_messages: String,
    mach: String,
    os: String,
    is_64: String,
    comp_name: String,
    logon_name: String,
    user_region: String,
    display_language: String,
    logical_cores: String,
    physical_cores: String,
    cpu_freq: String,
    cpu_vendor: String,
    cpu_model: String,
    memory: String,

    // instuction sets
    has_mmx: String,
    has_3DNow: String,
    has_FMA3: String,
    has_FMA4: String,
    has_SSE: String,
    has_SSE2: String,
    has_SSE3: String,
    has_SSSE3: String,
    has_SSE41: String,
    has_SSE42: String,
    has_AVX: String,
    has_AVX2: String,
    has_AVX512F: String,
    has_AVX512BW: String,
    has_AVX512CD: String,
    has_AVX512DQ: String,
    has_AVX512ER: String,
    has_AVX512IFMA: String,
    has_AVX512PF: String,
    has_AVX512VBMI: String,
    has_AVX512VL: String,
    has_AVX512VPOPCNTDQ: String,
    has_Neon: String,

    client_language: String
}
/*
#[derive(Clone, Copy)]
struct Instruct<'a> {
    name: &'a str,
    value: &'a str
}
#[derive(Clone, Copy)]
struct Stat<'a> {
    name: &'a str,
    value: &'a str
}

trait Insertion {
    fn new(n: &str, v: &String) -> Result<Instruct<'static>, &'static str>;
    fn compare(&mut self, original: &mut HashMap<String, AttributeValue>) -> bool;
}
impl Insertion for Instruct<'static> {
    fn new(n: &str, v: &String) -> Result<Instruct<'static>, &'static str> {
        if v.len() != 1 {
            return Err("Invalid stat");
        }
        if v != "1" && v != "0" && &v.to_ascii_lowercase() != "x" {
            return Err("Invalid stat");
        }
        return Ok(Instruct {name: n, value: &cleanse(&v, "")});
    }
    fn compare(&mut self, original: &mut HashMap<String, AttributeValue>) -> bool {
        let og = original.get("Instructions").unwrap().m.as_ref().unwrap().get(self.name).unwrap().s.as_ref().unwrap().to_owned();
        if og == self.value {
            return true;
        }
        if self.value.len() == 0 || self.value.to_ascii_lowercase() == "x" {
            self.value = &og;
            return true;
        }
        return false;
    }
}

trait Stats {
    fn new<'a>(n: &'a str, v: &'a String) -> Stat<'a>;
    fn compare(&mut self, original: &mut HashMap<String, AttributeValue>) -> bool;
} 

impl Stats for Stat<'_> {
    fn new<'a>(n:  &'a str, v: &'a String) -> Stat<'a> {
        return Stat {name: n, value: &cleanse(&v, ",-()")};
    }
    fn compare(&mut self, original: &mut HashMap<String, AttributeValue>) -> bool {
        let og = original.get("Stats").unwrap().m.as_ref().unwrap().get(self.name).unwrap().s.as_ref().unwrap().to_owned();
        if &og == &self.value {
            return true;
        }
        if self.value.len() == 0 || &self.value.to_ascii_lowercase() == "x" {
            self.value = &og.to_string();
            return true;
        }
        return false;
    }
}
*/

fn max_machines(resp: &str, num_machs: &usize) -> String {
    let result = resp.to_owned();
    if result.contains("{ratio}") {
        let mut text = num_machs.to_string();
        text.push('/');
        text.push_str(&num_machs.to_string());
        return result.replace("{ratio}", &text);
        
    }
    return result;
}




/**
 * Get query string parameter, cleanse it with potential extra characters
 * Returns error if the param doesn't exist in the query string
 */
fn get_q (q_string: &QueryMap, name: &str, extra: &str) -> Result<String, String> {
    let get = q_string.first(&name);
    if get.is_none() {
        return Err(format!("Missing {} param", &name));
    }
    return Ok(cleanse(&get.unwrap().to_string(), &extra));
}

/**
 * Get query string parameter, don't cleanse it
 * Returns error if the param doesn't exist in the query string
 */
fn get_c(q_string: &QueryMap, name: &str) -> Result<String, String> {
    let get = q_string.first(&name);
    if get.is_none() {
        return Err(format!("Missing {} param", &name));
    }
    return Ok(get.unwrap().to_string());
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
#[allow(non_snake_case)]
async fn function_handler(event: Request) -> Result<Response<String>, Error> {
    // Extract some useful information from the request

    // Return something that implements IntoResponse.
    // It will be serialized to the right response event automatically by the runtime
    
    /*
    let params = event.query_string_parameters().to_query_string();
    
    if params.len() > 0 {
        return auto_response(true, 403, "Error I1: Invalid request.");
    }
    */
    let params = event.query_string_parameters();
    if event.method() != lambda_http::http::Method::POST {
        return auto_response(true, 403, "Invalid request.");
    }
    //let payload = event.body();

    let company_r = get_q(&params, "company", "");
    if company_r.is_err() {
        return auto_response(true, 400, &company_r.unwrap_err());
    }
    let company = company_r.unwrap();

    let license_code_input_r = get_q(&params, "license_code", "");
    if license_code_input_r.is_err() {
        return auto_response(true, 400, &license_code_input_r.unwrap_err());
    }
    let license_code_input = license_code_input_r.unwrap();

    let use_personalization: String;
    let use_personalization_r = get_c(&params, "personalized_messages");
    if use_personalization_r.is_err() {
        use_personalization = "0".to_string();
        //return auto_response(true, 400, &use_personalization_r.unwrap_err());
    }else{
        use_personalization = use_personalization_r.unwrap().to_owned();
    }
    let plugin_r = get_q(&params, "product", "");
    if plugin_r.is_err() {
        return auto_response(true, 400, &plugin_r.unwrap_err());
    }
    let plugin = plugin_r.unwrap();

    let mach_r = get_q(&params, "mach", ",");
    if mach_r.is_err() {
        return auto_response(true, 400, &mach_r.unwrap_err());
    }
    let mach = mach_r.unwrap();

    let comp_name_r = get_c(&params, "comp_name");
    if comp_name_r.is_err() {
        return auto_response(true, 400, &comp_name_r.unwrap_err());
    }
    let comp_name = comp_name_r.unwrap();

    let logon_name_r = get_c(&params, "logon_name");
    if logon_name_r.is_err() {
        return auto_response(true, 400, &logon_name_r.unwrap_err());
    }
    let logon_name = logon_name_r.unwrap();

    let user_region_r = get_c(&params, "user_region");
    if user_region_r.is_err() {
        return auto_response(true, 400, &user_region_r.unwrap_err());
    }
    let user_region = user_region_r.unwrap();

    let display_language_r = get_c(&params, "display_language");
    if display_language_r.is_err() {
        return auto_response(true, 400, &display_language_r.unwrap_err());
    }
    let display_language = display_language_r.unwrap();

    let logical_cores_r = get_c(&params, "logical_cores");
    if logical_cores_r.is_err() {
        return auto_response(true, 400, &logical_cores_r.unwrap_err());
    }
    let logical_cores = logical_cores_r.unwrap();

    let physical_cores_r = get_c(&params, "physical_cores");
    if physical_cores_r.is_err() {
        return auto_response(true, 400, &physical_cores_r.unwrap_err());
    }
    let physical_cores = physical_cores_r.unwrap();

    let cpu_freq_r = get_c(&params, "cpu_freq");
    if cpu_freq_r.is_err() {
        return auto_response(true, 400, &cpu_freq_r.unwrap_err());
    }
    let cpu_freq = cpu_freq_r.unwrap();

    let cpu_vendor_r = get_c(&params, "cpu_vendor");
    if cpu_vendor_r.is_err() {
        return auto_response(true, 400, &cpu_vendor_r.unwrap_err());
    }
    let cpu_vendor = cpu_vendor_r.unwrap();

    let cpu_model_r = get_c(&params, "cpu_model");
    if cpu_model_r.is_err() {
        return auto_response(true, 400, &cpu_model_r.unwrap_err());
    }
    let cpu_model = cpu_model_r.unwrap();

    let memory_r = get_c(&params, "memory");
    if memory_r.is_err() {
        return auto_response(true, 400, &memory_r.unwrap_err());
    }
    let memory = memory_r.unwrap();

    let os_r = get_c(&params, "os");
    if os_r.is_err() {
        return auto_response(true, 400, &os_r.unwrap_err());
    }
    let os = os_r.unwrap();

    let is_64_r = get_c(&params, "is_64");
    if is_64_r.is_err() {
        return auto_response(true, 400, &is_64_r.unwrap_err());
    }
    let is_64 = is_64_r.unwrap();



    let has_mmx_r = get_c(&params, "has_mmx");
    if has_mmx_r.is_err() {
        return auto_response(true, 400, &has_mmx_r.unwrap_err());
    }
    let has_mmx = has_mmx_r.unwrap();

    let has_3DNow_r = get_c(&params, "has_3DNow");
    if has_3DNow_r.is_err() {
        return auto_response(true, 400, &has_3DNow_r.unwrap_err());
    }
    let has_3DNow = has_3DNow_r.unwrap();

    let has_FMA3_r = get_c(&params, "has_FMA3");
    if has_FMA3_r.is_err() {
        return auto_response(true, 400, &has_FMA3_r.unwrap_err());
    }
    let has_FMA3 = has_FMA3_r.unwrap();

    let has_FMA4_r = get_c(&params, "has_FMA4");
    if has_FMA4_r.is_err() {
        return auto_response(true, 400, &has_FMA4_r.unwrap_err());
    }
    let has_FMA4 = has_FMA4_r.unwrap();

    let has_SSE_r = get_c(&params, "has_SSE");
    if has_SSE_r.is_err() {
        return auto_response(true, 400, &has_SSE_r.unwrap_err());
    }
    let has_SSE = has_SSE_r.unwrap();

    let has_SSE2_r = get_c(&params, "has_SSE2");
    if has_SSE2_r.is_err() {
        return auto_response(true, 400, &has_SSE2_r.unwrap_err());
    }
    let has_SSE2 = has_SSE2_r.unwrap();

    let has_SSE3_r = get_c(&params, "has_SSE3");
    if has_SSE3_r.is_err() {
        return auto_response(true, 400, &has_SSE3_r.unwrap_err());
    }
    let has_SSE3 = has_SSE3_r.unwrap();

    let has_SSSE3_r = get_c(&params, "has_SSSE3");
    if has_SSSE3_r.is_err() {
        return auto_response(true, 400, &has_SSSE3_r.unwrap_err());
    }
    let has_SSSE3 = has_SSSE3_r.unwrap();

    let has_SSE41_r = get_c(&params, "has_SSE41");
    if has_SSE41_r.is_err() {
        return auto_response(true, 400, &has_SSE41_r.unwrap_err());
    }
    let has_SSE41 = has_SSE41_r.unwrap();

    let has_SSE42_r = get_c(&params, "has_SSE42");
    if has_SSE42_r.is_err() {
        return auto_response(true, 400, &has_SSE42_r.unwrap_err());
    }
    let has_SSE42 = has_SSE42_r.unwrap();

    let has_AVX_r = get_c(&params, "has_AVX");
    if has_AVX_r.is_err() {
        return auto_response(true, 400, &has_AVX_r.unwrap_err());
    }
    let has_AVX = has_AVX_r.unwrap();

    let has_AVX2_r = get_c(&params, "has_AVX2");
    if has_AVX2_r.is_err() {
        return auto_response(true, 400, &has_AVX2_r.unwrap_err());
    }
    let has_AVX2 = has_AVX2_r.unwrap();

    let has_AVX512F_r = get_c(&params, "has_AVX512F");
    if has_AVX512F_r.is_err() {
        return auto_response(true, 400, &has_AVX512F_r.unwrap_err());
    }
    let has_AVX512F = has_AVX512F_r.unwrap();

    let has_AVX512BW_r = get_c(&params, "has_AVX512BW");
    if has_AVX512BW_r.is_err() {
        return auto_response(true, 400, &has_AVX512BW_r.unwrap_err());
    }
    let has_AVX512BW = has_AVX512BW_r.unwrap();

    let has_AVX512CD_r = get_c(&params, "has_AVX512CD");
    if has_AVX512CD_r.is_err() {
        return auto_response(true, 400, &has_AVX512CD_r.unwrap_err());
    }
    let has_AVX512CD = has_AVX512CD_r.unwrap();

    let has_AVX512DQ_r = get_c(&params, "has_AVX512DQ");
    if has_AVX512DQ_r.is_err() {
        return auto_response(true, 400, &has_AVX512DQ_r.unwrap_err());
    }
    let has_AVX512DQ = has_AVX512DQ_r.unwrap();

    let has_AVX512ER_r = get_c(&params, "has_AVX512ER");
    if has_AVX512ER_r.is_err() {
        return auto_response(true, 400, &has_AVX512ER_r.unwrap_err());
    }
    let has_AVX512ER = has_AVX512ER_r.unwrap();

    let has_AVX512IFMA_r = get_c(&params, "has_AVX512IFMA");
    if has_AVX512IFMA_r.is_err() {
        return auto_response(true, 400, &has_AVX512IFMA_r.unwrap_err());
    }
    let has_AVX512IFMA = has_AVX512IFMA_r.unwrap();

    let has_AVX512PF_r = get_c(&params, "has_AVX512PF");
    if has_AVX512PF_r.is_err() {
        return auto_response(true, 400, &has_AVX512PF_r.unwrap_err());
    }
    let has_AVX512PF = has_AVX512PF_r.unwrap();

    let has_AVX512VBMI_r = get_c(&params, "has_AVX512VBMI");
    if has_AVX512VBMI_r.is_err() {
        return auto_response(true, 400, &has_AVX512VBMI_r.unwrap_err());
    }
    let has_AVX512VBMI = has_AVX512VBMI_r.unwrap();

    let has_AVX512VL_r = get_c(&params, "has_AVX512VL");
    if has_AVX512VL_r.is_err() {
        return auto_response(true, 400, &has_AVX512VL_r.unwrap_err());
    }
    let has_AVX512VL = has_AVX512VL_r.unwrap();

    let has_AVX512VPOPCNTDQ_r = get_c(&params, "has_AVX512VPOPCNTDQ");
    if has_AVX512VPOPCNTDQ_r.is_err() {
        return auto_response(true, 400, &has_AVX512VPOPCNTDQ_r.unwrap_err());
    }
    let has_AVX512VPOPCNTDQ = has_AVX512VPOPCNTDQ_r.unwrap();

    let has_Neon_r = get_c(&params, "has_Neon");
    if has_Neon_r.is_err() {
        return auto_response(true, 400, &has_Neon_r.unwrap_err());
    }
    let has_Neon = has_Neon_r.unwrap();


    let client_language_r = get_c(&params, "client_language");
    if client_language_r.is_err() {
        return auto_response(true, 400, &client_language_r.unwrap_err());
    }
    let client_language = client_language_r.unwrap();
    






    //match payload {
        //Body::Text(contents) => {
            // CONSTANTS


            //////////////////
            let client: DynamoDbClient = DynamoDbClient::new(Region::UsEast1);

            //let rq_check: Result<MyRequest, serde_json::Error> = serde_json::from_str(contents);
            //if rq_check.is_err() {
                //return auto_response(true, 400, &format!("Format issue: {:?}", rq_check.unwrap_err().to_string()) )
            //}
            //let rq = rq_check.unwrap();
            

            
            //let company = cleanse(&rq.company, "");
            //let license_code = rq.license_code.replace('-',"").escape_unicode().to_string().escape_default().to_string();
            //let license_code_input = cleanse(&rq.license_code, "");
            let is_offline_license = &license_code_input.len() > &20;
            let mut offline_code: String = "".to_owned();
            if is_offline_license {
                offline_code = license_code_input.to_owned().substring(20, license_code_input.len()).to_owned();
            }
            let license_code = license_code_input.substring(0, 20).to_owned();

            //let plugin = cleanse(&rq.product, "");
            //let mach = rq.mach.escape_unicode().to_string().escape_default().to_string();
            //let mach = cleanse(&rq.mach, ",");
         
            // stats stuff
///////////////////////////////////////////////
            
            let mut cpu_stats: Vec<(String, String)> = Vec::new();
            cpu_stats.push(("CompName".to_owned(), comp_name.to_owned()));
            cpu_stats.push(("LogonName".to_owned(), logon_name));
            cpu_stats.push(("UserRegion".to_owned(), user_region));
            cpu_stats.push(("DisplayLanguage".to_owned(), display_language));
            cpu_stats.push(("LogicalCores".to_owned(), logical_cores));
            cpu_stats.push(("PhysicalCores".to_owned(), physical_cores));
            cpu_stats.push(("CPUFreq".to_owned(), cpu_freq));
            cpu_stats.push(("CPUVendor".to_owned(), cpu_vendor));
            cpu_stats.push(("CPUModel".to_owned(), cpu_model));
            cpu_stats.push(("Memory".to_owned(), memory));            
            cpu_stats.push(("OS".to_owned(), os.to_owned()));
            cpu_stats.push(("is64".to_owned(), is_64));


            /*
            let mut cpu_stats: Vec<Stat> = Vec::new();
            cpu_stats.push(Stat::new("CompName", &rq.comp_name));
            cpu_stats.push(Stat::new("LogonName", &rq.logon_name));
            cpu_stats.push(Stat::new("UserRegion", &rq.user_region));
            cpu_stats.push(Stat::new("DisplayLanguage", &rq.display_language));
            cpu_stats.push(Stat::new("LogicalCores", &rq.logical_cores));
            cpu_stats.push(Stat::new("PhysicalCores", &rq.physical_cores));
            cpu_stats.push(Stat::new("CPUFreq", &rq.cpu_freq));
            cpu_stats.push(Stat::new("CPUVendor", &rq.cpu_vendor));
            cpu_stats.push(Stat::new("CPUModel", &rq.cpu_model));
            cpu_stats.push(Stat::new("Memory", &rq.memory));
            */
            
            // stats bools
            let mut instructions: Vec<(String, String)> = Vec::new();
            
            instructions.push(("has_MMX".to_owned(), has_mmx));
            instructions.push(("has_3DNow".to_owned(), has_3DNow));
            instructions.push(("has_FMA3".to_owned(), has_FMA3));
            instructions.push(("has_FMA4".to_owned(), has_FMA4));
            instructions.push(("has_SSE".to_owned(), has_SSE));
            instructions.push(("has_SSE2".to_owned(), has_SSE2));
            instructions.push(("has_SSE3".to_owned(), has_SSE3));
            instructions.push(("has_SSSE3".to_owned(), has_SSSE3));
            instructions.push(("has_SSE41".to_owned(), has_SSE41));
            instructions.push(("has_SSE42".to_owned(), has_SSE42));
            instructions.push(("has_AVX".to_owned(), has_AVX));
            instructions.push(("has_AVX2".to_owned(), has_AVX2));
            instructions.push(("has_AVX512F".to_owned(), has_AVX512F));
            instructions.push(("has_AVX512BW".to_owned(), has_AVX512BW));
            instructions.push(("has_AVX512CD".to_owned(), has_AVX512CD));
            instructions.push(("has_AVX512DQ".to_owned(), has_AVX512DQ));
            instructions.push(("has_AVX512ER".to_owned(), has_AVX512ER));
            instructions.push(("has_AVX512IFMA".to_owned(), has_AVX512IFMA));
            instructions.push(("has_AVX512PF".to_owned(), has_AVX512PF));
            instructions.push(("has_AVX512VBMI".to_owned(), has_AVX512VBMI));
            instructions.push(("has_AVX512VL".to_owned(), has_AVX512VL));
            instructions.push(("has_AVX512VPOPCNTDQ".to_owned(), has_AVX512VPOPCNTDQ));
            instructions.push(("hasNeon".to_owned(), has_Neon));
            


            /*
            let mut instructions: Vec<Result<Instruct, &str>> = Vec::new();

            instructions.push(Instruct::new("has_MMX", &rq.has_mmx));
            instructions.push(Instruct::new("has_3DNow", &rq.has_3DNow));
            instructions.push(Instruct::new("has_FMA3", &rq.has_FMA3));
            instructions.push(Instruct::new("has_FMA4", &rq.has_FMA4));
            instructions.push(Instruct::new("has_SSE", &rq.has_SSE));
            instructions.push(Instruct::new("has_SSE2", &rq.has_SSE2));
            instructions.push(Instruct::new("has_SSE3", &rq.has_SSE3));
            instructions.push(Instruct::new("has_SSSE3", &rq.has_SSSE3));
            instructions.push(Instruct::new("has_SSE41", &rq.has_SSE41));
            instructions.push(Instruct::new("has_SSE42", &rq.has_SSE42));
            instructions.push(Instruct::new("has_AVX", &rq.has_AVX));
            instructions.push(Instruct::new("has_AVX2", &rq.has_AVX2));
            instructions.push(Instruct::new("has_AVX512F", &rq.has_AVX512F));
            instructions.push(Instruct::new("has_AVX512BW", &rq.has_AVX512BW));
            instructions.push(Instruct::new("has_AVX512CD", &rq.has_AVX512CD));
            instructions.push(Instruct::new("has_AVX512DQ", &rq.has_AVX512DQ));
            instructions.push(Instruct::new("has_AVX512ER", &rq.has_AVX512ER));
            instructions.push(Instruct::new("has_AVX512IFMA", &rq.has_AVX512IFMA));
            instructions.push(Instruct::new("has_AVX512PF", &rq.has_AVX512PF));
            instructions.push(Instruct::new("has_AVX512VBMI", &rq.has_AVX512VBMI));
            instructions.push(Instruct::new("has_AVX512VL", &rq.has_AVX512VL));
            instructions.push(Instruct::new("has_AVX512VPOPCNDQ", &rq.has_AVX512VPOPCNDQ));
            instructions.push(Instruct::new("hasNeon", &rq.has_Neon));
            */

            // new_instruc
            for inst in &instructions {
                let test_out = inst.1.to_ascii_lowercase();
                if &test_out != "x" && &test_out != "1" && &test_out != "0" {
                    return auto_response(true, 400, "Invalid stats configuration.");
                }
            }
            

            //let client_language = &rq.client_language;
            let mut combined_partition_key = company.to_owned();
            combined_partition_key.push_str(&license_code);
            //default_response.body_mut().push_str(&format!(" combined = {}", &combined_partition_key));
            let encrypted_partition_key = encrypt_id(&combined_partition_key, true, true);



            // batch get
            // change these id names later
            let mut license_key_map: HashMap<String, AttributeValue> = HashMap::new();
            //license_key_map.insert("[CompanyID][License]".to_owned(),
            license_key_map.insert("id1".to_owned(),

                AttributeValue {
                    s: Some(encrypted_partition_key.to_owned()),
                    ..AttributeValue::default()
                }
            );
            license_key_map.insert("id2".to_owned(),
                AttributeValue {
                    s: Some("all".to_owned()),
                    ..AttributeValue::default()
                }
            );

            
            let mut plugin_partition_key: String = company.to_owned();
            plugin_partition_key.push_str(&plugin);
            plugin_partition_key = encrypt_id(&plugin_partition_key, true, false);
            
            let mut plugins_key_map: HashMap<String, AttributeValue> = HashMap::new(); 
            plugins_key_map.insert("id".to_owned(),
                AttributeValue {
                    s: Some(plugin_partition_key.to_owned()),
                    ..AttributeValue::default()
                }
            );

            let mut machine_key_map: HashMap<String,AttributeValue> = HashMap::new();
            machine_key_map.insert("id".to_owned(),
                AttributeValue {
                    s: Some(mach.to_owned()),
                    ..AttributeValue::default()
                }
            );

            //let keys_vec: Vec<HashMap<String, AttributeValue>> = vec![license_key_map];
            let mut get_req_items: HashMap<String, KeysAndAttributes> = HashMap::new();
            get_req_items.insert(
                LICENSE_TABLE_NAME.to_owned(),
                KeysAndAttributes {
                    consistent_read: Some(true),
                    keys: vec![license_key_map.to_owned()],
                    ..Default::default()
                }
            );

            get_req_items.insert(
                PLUGINS_TABLE_NAME.to_owned(),
                KeysAndAttributes {
                    consistent_read: Some(true),
                    keys: vec![plugins_key_map.to_owned()],
                    ..Default::default()
                }
            );

            get_req_items.insert(
                MACHINES_TABLE_NAME.to_owned(),
                KeysAndAttributes {
                    consistent_read: Some(true),
                    keys: vec![machine_key_map.to_owned()],
                    ..Default::default()
                }
            );

            let batch_get = match client.batch_get_item(BatchGetItemInput {
                request_items: get_req_items,
                ..BatchGetItemInput::default()
            }).await {
                Err(err) => {
                    return auto_response(
                        true, 
                        500, 
                        &format!("Error BGI-1: {}. Please contact Plugin Licensor for support.", err));
                },
                Ok(batch_get) => batch_get,
            };
            if batch_get.responses.is_none() {
                return auto_response(true, 400, "Error F1: Invalid plugin configuration.");
            }

            let license_item = batch_get.responses.as_ref().unwrap().get(LICENSE_TABLE_NAME);
            let plugins_item = batch_get.responses.as_ref().unwrap().get(PLUGINS_TABLE_NAME);
            let machine_item = batch_get.responses.as_ref().unwrap().get(MACHINES_TABLE_NAME);
            
            let mut machine_exists: bool = false;
            let mut machine_list_item: HashMap<String, AttributeValue> = HashMap::new();
            if machine_item.is_some() {
                if machine_item.unwrap().len() != 0 {
                    machine_exists = true;
                    machine_list_item = machine_item.unwrap().get(0).unwrap().to_owned();
                }
            }
            
            if plugins_item.is_none() {
                return auto_response(true, 400, "Error F2: Invalid plugin configuration.");
            }
            let plugins_list_opt_f = plugins_item.unwrap();
            if plugins_list_opt_f.len() != 1 {
                return auto_response(true, 400, "Error F6: Invalid plugin configuration.");
            }
            let plugin_item = plugins_list_opt_f[0].to_owned();
            let language_support_map_opt = plugin_item.get("language_support");
            if language_support_map_opt.is_none() {
                return auto_response(true, 500, "Issue with language support!");
            }
            let language_support_maps = language_support_map_opt.unwrap().m.as_ref().unwrap().to_owned();
            
            let language_support_opt = language_support_maps.get(&client_language);
            if language_support_opt.is_none() {
                return auto_response(true, 400, "Issue with language support: Client language not supported");
            }

            let language_support = language_support_opt.unwrap().m.as_ref().unwrap().to_owned();

            if license_item.is_none() {
                //let mut custom_response_check = client_language.to_owned();
                //custom_response_check.push_str("NoLicenseFound");
                //let custom_response = plugins_item.unwrap()[0].get(&custom_response_check);
                let custom_response = language_support.get("NoLicenseFound");
                if custom_response.is_none() {
                    return auto_response(true, 500, "Error AJ741e");
                }
                return auto_response(true, 400, custom_response.unwrap().s.as_ref().to_owned().unwrap());
            }
            let plugins_list_items = plugins_item.unwrap().to_owned();
            if plugins_list_items.len() == 0 {
                // DBG DELETE
                /*
                let mut resp = format!("PLI: {:?}", plugins_list_items);
                resp.push_str(r#" OOPSIE"#);
                resp.push_str(&format!(r#"\n{:?}"#, &plugin_partition_key));
                 */
                return auto_response(true, 400, "Error F3: Invalid plugin configuration.");
                
                //return auto_response(true, 400, &resp);
            }
            //return auto_response(true, 400, "Got to line 713!");
            let license_list_items = license_item.unwrap().to_owned();
            if license_list_items.len() == 0 {
                //let mut custom_response_check = client_language.to_owned();
                //custom_response_check.push_str("NoLicenseFound");
                //let custom_response = plugins_item.unwrap()[0].get(&custom_response_check);
                let custom_response = language_support.get("NoLicenseFound");
                if custom_response.is_none() {
                    increment_plugin_calls_slow(client, plugins_key_map).await;
                    return auto_response(true, 500, "Error AJ766w");
                }
                return auto_response(true, 400, custom_response.unwrap().s.as_ref().to_owned().unwrap());
            }else if license_list_items.len() > 1{
                // there should only be one item
                return auto_response(true, 500, "Error A741");
            }

            

            // license_list_items = a vector with 1 element, which is a hashmap
            // same for plugins_list_items

            // debugging
            //return auto_response(true, 400, "Got to line 730!");
            //let plugin_item = plugins_item.unwrap()[0].to_owned();
            //let mut success_message = client_language.to_owned();
            //success_message.push_str("Success");
            let success_message_found = language_support.get("Success");
            /*
            let mut all_data = "".to_owned();
            for key in plugin_item.keys() {
                all_data.push_str(key);
                all_data.push_str(", ");
            }
            return auto_response(true, 400, &all_data);
            */
            
            match success_message_found {
                Some(message) => {
                    let license_data_whole = &license_list_items[0];
                    let email = license_data_whole.get("Email").unwrap().s.as_ref().unwrap().to_owned();
                    let uuid_opt = license_data_whole.get("uuid");
                    if uuid_opt.is_none() {
                        return auto_response(true, 500, "Error A770: No UUID found");
                    }
                    let uuid_attr = uuid_opt.unwrap().to_owned();
                    let uuid_str_opt = uuid_attr.s.as_ref();
                    if uuid_str_opt.is_none() {
                        return auto_response(true, 500, "Error A775: No UUID found.");
                    }
                    let uuid = uuid_str_opt.unwrap().to_owned();
                    let mut user_key_map: HashMap<String, AttributeValue> = HashMap::new();
                    user_key_map.insert(
                        "company".to_owned(),
                        AttributeValue {
                            s: Some(company.to_owned()),
                            ..Default::default()
                        }
                    );
                    user_key_map.insert(
                        "uuid".to_owned(),
                        AttributeValue {
                            s: Some(uuid.to_owned()),
                            ..Default::default()
                        }
                    );

                    let get_user: HashMap<String, AttributeValue>;

                    let messages_enabled = parse_bool(&use_personalization) && plugin_item.get("messagesEnabled").unwrap().bool.as_ref().to_owned().unwrap().to_owned();
                    let messages: Option<Vec<String>>;
                    let messages_frequency: Option<String>;
                    if messages_enabled.to_owned() {
                        let mut batch_get_keys_2: HashMap<String, KeysAndAttributes> = HashMap::new();

                        batch_get_keys_2.insert(
                            USERS_TABLE_NAME.to_owned(),
                            KeysAndAttributes {
                                consistent_read: Some(true),
                                keys: vec![user_key_map.to_owned()],
                                ..Default::default()
                            }
                        );

                        let mut message_keys: Vec<HashMap<String, AttributeValue>> = Vec::new();

                        let mut c_name_key: HashMap<String, AttributeValue> = HashMap::new();
                        c_name_key.insert(
                            "id".to_owned(),
                            AttributeValue {
                                s: Some(comp_name.to_owned()),
                                ..Default::default()
                            }
                        );
                        if !email.eq("Not disclosed") {
                            let mut email_key: HashMap<String, AttributeValue> = HashMap::new();
                            email_key.insert(
                                "id".to_owned(),
                                AttributeValue {
                                    s: Some(email.to_owned()),
                                    ..Default::default()
                                }
                            );
                            message_keys.push(email_key.to_owned());
                        }
                        let ip_header = event.headers().get("X-Forwarded-For")
                            .and_then(|value| value.to_str().ok()).unwrap_or("unknown");
                        let end = ip_header.find(",");
                        let ip: &str;
                        if end.is_some(){
                            ip = ip_header.substring(0, end.unwrap());
                        }else{
                            ip = ip_header;
                        }                        
                        let mut ip_key: HashMap<String, AttributeValue> = HashMap::new();
                        ip_key.insert(
                            "id".to_owned(),
                            AttributeValue {
                                s: Some(ip.to_owned()),
                                ..Default::default()
                            }
                        );

                        if !ip.eq("unknown") {
                            message_keys.push(ip_key.to_owned());
                        }
                        message_keys.push(c_name_key.to_owned());


                        batch_get_keys_2.insert(
                            MESSAGES_TABLE_NAME.to_owned(),
                            KeysAndAttributes {
                                consistent_read: Some(true),
                                keys: message_keys.to_owned(),
                                ..Default::default()
                            }
                        );

                        let second_batch_get_input = BatchGetItemInput {
                            request_items: batch_get_keys_2.to_owned(),
                            ..Default::default()
                        };
                        let batch_output_result = client.batch_get_item(second_batch_get_input).await;
                        if batch_output_result.is_err() {
                            return auto_response(true, 500, "Error A0868");
                        }
                        let batch_output_opt = batch_output_result.unwrap().responses;
                        if batch_output_opt.is_none() {
                            return auto_response(true, 500, "Error A0872: User not found.");
                        }
                        let batch_output = batch_output_opt.unwrap();
                        let user_map_opt_vec = batch_output.get(USERS_TABLE_NAME);
                        if user_map_opt_vec.is_none() {
                            return auto_response(true, 500, "Error A0879: No user found.");
                        }
                        let user_map_vec = user_map_opt_vec.unwrap();
                        if user_map_vec.len() != 1 {
                            return auto_response(true, 500, "Error A0883: Error fetching user.");
                        }
                        get_user = user_map_vec[0].to_owned();

                        let messages_opt = batch_output.get(MESSAGES_TABLE_NAME);
                        if messages_opt.is_some() {
                            let messages_vec_map = messages_opt.unwrap().to_owned();
                            let mut temp_messages_vec: Vec<String> = Vec::new();
                            let mut temp_frequency: u32 = 0;
                            for item in messages_vec_map {
                                let item_messages_opt = item.get("messages");
                                if item_messages_opt.is_some() {
                                    let item_messages = item_messages_opt.unwrap().ss.as_ref().unwrap().to_owned();
                                    for m in item_messages {
                                        if !temp_messages_vec.contains(&m) {
                                            temp_messages_vec.push(m.to_owned());
                                        }
                                    }
                                    let found_freq = item.get("frequency").unwrap().n.as_ref().unwrap().parse::<u32>().unwrap();
                                    if &found_freq > &temp_frequency {
                                        temp_frequency = found_freq.to_owned();
                                    }
                                }
                            }
                            if temp_frequency == 0 as u32 || temp_messages_vec.len() == 0 {
                                messages_frequency = None;
                                messages = None;
                            }else{
                                messages_frequency = Some(temp_frequency.to_string());
                                messages = Some(temp_messages_vec.to_owned());
                            }
                        }else{
                            messages_frequency = None;
                            messages = None;
                        }
                    }else{
                        messages = None;
                        messages_frequency = None;
                        
                        let get_user_item = client.get_item(
                            rusoto_dynamodb::GetItemInput { 
                                consistent_read: Some(true), 
                                key: user_key_map.to_owned(), 
                                table_name: USERS_TABLE_NAME.to_owned(),
                                ..Default::default()
                            }
                        ).await;
                        
                        if get_user_item.is_err() {
                            return auto_response(true, 500, "Error A803: Please try again in a few moments. If it continues to occur, please contact Plugin Licensor.");
                        }
                        let get_user_opt = get_user_item.unwrap().item;
                        if get_user_opt.is_none() {
                            return auto_response(true, 500, "Error A807: User not found.");
                        }
                        get_user = get_user_opt.unwrap().to_owned();
                    }

                    
                    
                    let user_licenses_opt = get_user.get("licenses");
                    if user_licenses_opt.is_none() {
                        return auto_response(true, 500, "Error A812: No licenses found for user.");
                    }
                    let user_licenses_m_opt = user_licenses_opt.unwrap().m.as_ref();
                    if user_licenses_m_opt.is_none() {
                        return auto_response(true, 500, "Error A816: No user licenses found.");
                    }

                    // this map represents the User table item > licenses
                    let user_licenses_m = user_licenses_m_opt.unwrap().to_owned();
                    
                    // this map represents the User table item > licenses > [plugin]
                    let user_license_map_opt = user_licenses_m.get(&plugin);
                    if user_license_map_opt.is_none() {
                        return auto_response(true, 500, "Error A825: No license found in your user data.");
                    }
                    let user_license_map_attr_opt = user_license_map_opt.unwrap().m.as_ref();
                    if user_license_map_attr_opt.is_none() {
                        return auto_response(true, 500, "Error A829: No license found in your user data.");
                    }
                    let user_license_map = user_license_map_attr_opt.unwrap().to_owned();

                    // determine if user license map needs to be updated
                    let update_user_license_tuple = update_user_license_method(
                        user_license_map.to_owned(), 
                        mach.to_owned(),
                        os.to_owned(),
                        comp_name.to_owned()
                    );
                    /**
                     * .0 = bool, should it be updated
                     * .1 = the map entry that it should be updated to, Option
                     */
                    if update_user_license_tuple.is_err() {
                        return auto_response(
                            true, 
                            500, 
                            &format!("{}", update_user_license_tuple.unwrap_err())
                        )
                    }
                    let update_user_license_tup = update_user_license_tuple.unwrap();
                    let should_update_user_item = update_user_license_tup.0;
                    let new_user_mach_map_opt = update_user_license_tup.1;

                    let user_transact_item: Option<rusoto_dynamodb::TransactWriteItem>;
                    if should_update_user_item {
                        let mut new_machines_map = user_license_map.clone();
                        let machine_map_item = new_user_mach_map_opt.unwrap();
                        new_machines_map.insert(
                            "machines".to_owned(),
                            AttributeValue {
                                m: Some(machine_map_item.to_owned()),
                                ..Default::default()
                            }
                        );
                        let mut new_licenses_map = user_licenses_m.clone();
                        new_licenses_map.insert(
                            plugin.to_owned(),
                            AttributeValue {
                                m: Some(new_machines_map.to_owned()),
                                ..Default::default()
                            }
                        );
                        let mut new_user_map = get_user.clone();
                        new_user_map.insert(
                            "licenses".to_owned(),
                            AttributeValue {
                                m: Some(new_licenses_map.to_owned()),
                                ..Default::default()
                            }
                        );

                        let user_update_expr = vec!("#a = :a".to_owned());
                        let mut user_expr_attr_names: HashMap<String, String> = HashMap::new();
                        let mut user_expr_attr_vals: HashMap<String, AttributeValue> = HashMap::new();
                        user_expr_attr_names.insert(
                            "#a".to_owned(),
                            "licenses".to_owned()
                        );
                        user_expr_attr_vals.insert(
                            ":a".to_owned(),
                            AttributeValue {
                                m: Some(new_licenses_map.to_owned()),
                                ..Default::default()
                            }
                        );

                        user_transact_item = Some(
                            rusoto_dynamodb::TransactWriteItem {
                                update: Some(rusoto_dynamodb::Update { 
                                    expression_attribute_names: Some(user_expr_attr_names), 
                                    expression_attribute_values: Some(user_expr_attr_vals), 
                                    key: user_key_map.to_owned(), 
                                    table_name: USERS_TABLE_NAME.to_owned(), 
                                    update_expression: format!("SET {}", &user_update_expr.join(",")),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            }
                        );

                    }else{
                        user_transact_item = None;
                    }

                    let license_data_plugins_result = &license_data_whole.get("Plugins");
                    if license_data_plugins_result.is_none() {
                        return auto_response(true, 500, "Error AJ1491");
                    }
                    let license_data_plugins_map_attr = license_data_plugins_result.unwrap().m.as_ref();
                    if license_data_plugins_map_attr.is_none() {
                        return auto_response(true, 500, "Error AJ1495");
                    }
                    let license_data_plugins_map = license_data_plugins_map_attr.unwrap();

                    let license_data_plugin_result = license_data_plugins_map.get(&plugin);
                    if license_data_plugin_result.is_none() {
                        return auto_response(true, 500, "Error AJ1501");
                    }
                    let license_data_option = license_data_plugin_result.unwrap().m.as_ref();
                    if license_data_option.is_none() {
                        return auto_response(true, 500, "Error AJ1505");
                    }
                    let license_data = license_data_option.unwrap();

                    //let first_name = license_data.get("FirstName").unwrap().s.as_ref().unwrap().to_owned();
                    //let last_name = license_data.get("LastName").unwrap().s.as_ref().unwrap().to_owned();
                    let license_type = license_data.get("LicenseType").unwrap().s.as_ref().unwrap().to_owned();
                    //let email = license_data.get("Email");
                    let activation_time = license_data.get("ActivationTime");
                    
                    let mut online_machines = license_data.get("Online").unwrap().l.as_ref().unwrap().clone();
                    let mut offline_machines = license_data.get("Offline").unwrap().l.as_ref().unwrap().clone();
                    let license_active = license_data.get("LicenseActive").unwrap().bool.unwrap().to_owned();
                    let machines_allowed = license_data.get("MachinesAllowed").unwrap().n.as_ref().unwrap().to_string().parse::<usize>().unwrap();
                    let permanent_secret = license_data.get("OfflineSecret").unwrap().s.as_ref().unwrap().to_owned();
///////////////////////////////////////////
                    let machine_attribute_value = AttributeValue {
                        s: Some(mach.to_owned()),
                        ..Default::default()
                    };

                    let initial_total_machines = online_machines.len() + offline_machines.len();

                    // check if license is expired
                    let expiration = u64::from_str_radix(license_data.get("ExpiryTime").unwrap().s.as_ref().unwrap(), 36).unwrap();
                    if expiration != 0 && (!license_active || 
                            (&license_type == "Trial" && SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() > expiration) || 
                            (&license_type == "Beta" && SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() > expiration)
                            || (&license_type == "Subscription" && SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() > expiration + u64::from_str_radix(plugin_item.get("SubscriptionExpirationLenienceDays").unwrap().n.as_ref().unwrap(), 36).unwrap() * 86400)) {
                        //let mut error_resp = client_language.to_owned();
                        //error_resp.push_str("LicenseNoLongerActive");
                        
                        if license_active {
                            // make sure license isn't active
                            // set it to inactive
                            let mut update_license_map: HashMap<String, AttributeValue> = HashMap::new();
                            let license_update_expression = vec!["#a = :a".to_owned()];
                            
                            let mut license_expression_attribute_names: HashMap<String, String> = HashMap::new();
                            license_expression_attribute_names.insert(
                                "#a".to_owned(), "LicenseActive".to_owned());
                            update_license_map.insert(
                                ":a".to_owned(), AttributeValue {
                                    bool: Some(false), ..Default::default()
                                }
                            );
                            let _license_output = client.update_item(
                                rusoto_dynamodb::UpdateItemInput {
                                    key: license_key_map.to_owned(),
                                    table_name: LICENSE_TABLE_NAME.to_owned(),
                                    update_expression: Some(format!("SET {}", license_update_expression.join(","))),
                                    expression_attribute_names: Some(license_expression_attribute_names),
                                    expression_attribute_values: Some(update_license_map),
                                    ..Default::default()
                                }
                            ).await?;
                            
                        }
                        increment_plugin_calls_slow(client, plugins_key_map).await;
                        
                        return auto_response(true, 400, language_support.get("LicenseNoLongerActive").unwrap().s.as_ref().unwrap());
                    }
                    
                    
                    if &initial_total_machines <= &machines_allowed 
                        /* && !online_machines.contains(&mach) && !offline_machines.contains(&mach) */
                    {
                        if &initial_total_machines == &machines_allowed 
                            && !online_machines.contains(&machine_attribute_value)
                            && !offline_machines.contains(&machine_attribute_value)
                        {
                            //let mut error_resp_name = client_language.to_owned();
                            //error_resp_name.push_str("OverMaxMachines");
                            let max_response = max_machines(&language_support.get("OverMaxMachines").unwrap().s.as_ref().unwrap(), &initial_total_machines);
                            return auto_response(true, 200, &max_response);
                        }


                    //return auto_response(true, 200, "test");



                        // from here down, it will be a success response
                        if online_machines.contains(&machine_attribute_value) {
                            //increment_plugin_calls_slow();
                            if is_offline_license {
                                match perm_codes_equal(&offline_code, &permanent_secret, &license_type) {
                                    Ok(_x) => {
                                        // remove machine from online machines
                                        online_machines.retain(|x| *x != machine_attribute_value.clone());
                                        offline_machines.push(machine_attribute_value.to_owned());
////////////////////////
// Changing it to use one license table entry
                                        let license_update_expr = vec!(
                                            "#a = :a".to_owned()
                                        );
                                        let mut license_expr_attr_names: HashMap<String, String> = HashMap::new();
                                        license_expr_attr_names.insert(
                                            "#a".to_owned(),
                                            "Plugins".to_owned()
                                        );
                                        let license_expr_attr_vals_result = modify_hashmap(
                                            &license_data_whole, 
                                            &license_data, 
                                            &plugin, 
                                            Some(&online_machines), 
                                            Some(&offline_machines),
                                            None,
                                            None
                                        );

                                        if license_expr_attr_vals_result.is_err() {
                                            return auto_response(true, 500, &license_expr_attr_vals_result.unwrap_err().to_string());
                                        }
                                        let license_expr_attr_vals = license_expr_attr_vals_result.unwrap();

                                        
                                        let license_transact_item = rusoto_dynamodb::TransactWriteItem {
                                            update: Some(rusoto_dynamodb::Update {
                                                update_expression: format!("SET {}", &license_update_expr.join(",")),
                                                expression_attribute_names: Some(license_expr_attr_names),
                                                expression_attribute_values: Some(license_expr_attr_vals),
                                                key: license_key_map.to_owned(),
                                                table_name: LICENSE_TABLE_NAME.to_owned(),
                                                ..Default::default()
                                            }),
                                            ..Default::default()
                                        };

                                        let mut plug_update_names: HashMap<String, String> = HashMap::new();
                                        plug_update_names.insert("#a".to_owned(), "Calls".to_owned());
                                        let mut plug_update_vals: HashMap<String, AttributeValue> = HashMap::new();
                                        plug_update_vals.insert(":a".to_owned(),
                                            AttributeValue {
                                                n: Some(1.to_string()),
                                                ..Default::default()
                                        });

                                        let plugin_transact_item = rusoto_dynamodb::TransactWriteItem {
                                            update: Some(rusoto_dynamodb::Update {
                                                update_expression: "ADD #a :a".to_owned(),
                                                key: plugins_key_map.to_owned(),
                                                table_name: PLUGINS_TABLE_NAME.to_owned(),
                                                expression_attribute_names: Some(plug_update_names.to_owned()),
                                                expression_attribute_values: Some(plug_update_vals.to_owned()),
                                                ..Default::default()
                                            }),
                                            ..Default::default()
                                        };

                                        let mut transact_items: Vec<rusoto_dynamodb::TransactWriteItem> = Vec::new();
                                        transact_items.push(
                                            license_transact_item.to_owned()
                                        );
                                        transact_items.push(plugin_transact_item.to_owned());

                                        if user_transact_item.is_some() {
                                            transact_items.push(user_transact_item.unwrap());
                                        }
                                        
///////////////////////////////////////////////////////
// check new_expiry
                                        return transact_write(
                                            client, 
                                            transact_items.to_owned(), 
                                            &company, 
                                            messages.to_owned(),
                                            messages_enabled.to_owned(),
                                            messages_frequency.to_owned(),
                                            &plugin, 
                                            &mach, 
                                            &mut cpu_stats, 
                                            &mut instructions, 
                                            &mut machine_list_item.to_owned(), 
                                            &license_code, 
                                            language_support.to_owned(), 
                                            &plugin_item, 
                                            license_data, 
                                            &license_type, 
                                            machines_allowed, 
                                            initial_total_machines, 
                                            is_offline_license,
                                            &message,
                                            machine_exists,
                                            None).await;
                                        
                                    },
                                    Err(x) => {
                                        //let mut error_name = client_language.to_owned();
                                        //error_name.push_str(&x);
                                        let error_mess = language_support.get(&x).unwrap().s.as_ref().unwrap().to_owned();
                                        return auto_response(true, 200, &error_mess);
                                    }
                                };
                            }else{
                                // it is an online license
                                increment_plugin_calls_slow(client, plugins_key_map).await;
                                return success(&plugin, messages.to_owned(), messages_enabled.to_owned(), messages_frequency.to_owned(), &message, is_offline_license, initial_total_machines, machines_allowed, &license_type, license_data, &plugin_item, language_support.to_owned(), &mach, &license_code, None);
                            }
                        }else if offline_machines.contains(&machine_attribute_value) {
                            if is_offline_license {
                                match perm_codes_equal(&offline_code, &permanent_secret, &license_type) {
                                    Ok(_x) => {
                                        increment_plugin_calls_slow(client, plugins_key_map).await;
                                        return success(&plugin, messages.to_owned(), messages_enabled.to_owned(), messages_frequency.to_owned(), &message, is_offline_license, initial_total_machines, machines_allowed, &license_type, license_data, &plugin_item, language_support.to_owned(), &mach, &license_code, None);
                                    },
                                    Err(x) => {
                                        increment_plugin_calls_slow(client, plugins_key_map).await;
                                        //let mut error_name = client_language.to_owned();
                                        //error_name.push_str(&x);
                                        let error_mess = language_support.get(&x).unwrap().s.as_ref().unwrap().to_owned();
                                        return auto_response(true, 200, &error_mess);
                                    }
                                };
                            }else{
                                // remove machine from offline
                                // put in online
                                // add 1 to calls
                                offline_machines.retain(|x| *x != machine_attribute_value.clone());
                                online_machines.push(machine_attribute_value.to_owned());

                                let license_update_expr = vec!(
                                    "#a = :a".to_owned()
                                );
                                let mut license_expr_attr_names: HashMap<String, String> = HashMap::new();
                                license_expr_attr_names.insert(
                                    "#a".to_owned(),
                                    "Plugins".to_owned()
                                );
                                let license_expr_attr_vals_result = modify_hashmap(
                                    &license_data_whole, 
                                    &license_data, 
                                    &plugin, 
                                    Some(&online_machines), 
                                    Some(&offline_machines),
                                    None,
                                    None
                                );

                                if license_expr_attr_vals_result.is_err() {
                                    return auto_response(true, 500, &license_expr_attr_vals_result.unwrap_err().to_string());
                                }
                                let license_expr_attr_vals = license_expr_attr_vals_result.unwrap();


                                

                                let license_transact_item = rusoto_dynamodb::TransactWriteItem {
                                    update: Some(rusoto_dynamodb::Update {
                                        update_expression: format!("SET {}", &license_update_expr.join(",")),
                                        expression_attribute_names: Some(license_expr_attr_names),
                                        expression_attribute_values: Some(license_expr_attr_vals),
                                        key: license_key_map.to_owned(),
                                        table_name: LICENSE_TABLE_NAME.to_owned(),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                };
                                let mut plug_update_names: HashMap<String, String> = HashMap::new();
                                plug_update_names.insert("#a".to_owned(), "Calls".to_owned());
                                let mut plug_update_vals: HashMap<String, AttributeValue> = HashMap::new();
                                plug_update_vals.insert(":a".to_owned(),
                                    AttributeValue {
                                        n: Some(1.to_string()),
                                        ..Default::default()
                                });
    
                                let plugin_transact_item = rusoto_dynamodb::TransactWriteItem {
                                    update: Some(rusoto_dynamodb::Update {
                                        update_expression: "ADD #a :a".to_owned(),
                                        key: plugins_key_map.to_owned(),
                                        table_name: PLUGINS_TABLE_NAME.to_owned(),
                                        expression_attribute_names: Some(plug_update_names.to_owned()),
                                        expression_attribute_values: Some(plug_update_vals.to_owned()),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                };
                                let mut transact_items: Vec<rusoto_dynamodb::TransactWriteItem> = Vec::new();
                                transact_items.push(
                                    license_transact_item.to_owned()
                                );
                                transact_items.push(plugin_transact_item.to_owned());

                                if user_transact_item.is_some() {
                                    transact_items.push(user_transact_item.unwrap());
                                }

                                return transact_write(
                                    client,
                                    transact_items.to_owned(), 
                                    &company, 
                                    messages.to_owned(),
                                    messages_enabled.to_owned(),
                                    messages_frequency.to_owned(),
                                    &plugin, 
                                    &mach, 
                                    &mut cpu_stats, 
                                    &mut instructions, 
                                    &mut machine_list_item.to_owned(), 
                                    &license_code, 
                                    language_support.to_owned(), 
                                    &plugin_item, 
                                    license_data, 
                                    &license_type, 
                                    machines_allowed, 
                                    initial_total_machines, 
                                    is_offline_license,
                                    &message,
                                    machine_exists,
                                None).await;
                            }
                        }else if &initial_total_machines < &machines_allowed {

                            // use this to set activation time
                            // needs a little work
                            let license_update_expr = vec!["#a = :a".to_owned()];
                            let mut license_expr_attr_names: HashMap<String, String> = HashMap::new();
                            license_expr_attr_names.insert("#a".to_owned(), "Plugins".to_owned());
                            //let mut license_expr_attr_vals: HashMap<String, AttributeValue> = HashMap::new();
                            
                            let modify_offline_machines: Option<&Vec<AttributeValue>>;
                            let modify_online_machines: Option<&Vec<AttributeValue>>;
                            if is_offline_license {
                                match perm_codes_equal(&offline_code, &permanent_secret, &license_type) {
                                    Err(x) => {
                                        //let mut error_name = client_language.to_owned();
                                        //error_name.push_str(&x);
                                        let error_resp = language_support.get(&x).unwrap().s.as_ref().unwrap().to_owned();
                                        return auto_response(true, 200, &error_resp);
                                    },
                                    Ok(_x) => {
                                        offline_machines.push(machine_attribute_value.to_owned());
                                        modify_offline_machines = Some(&offline_machines);
                                        modify_online_machines = None;
                                    }
                                };

                            }else{
                                online_machines.push(machine_attribute_value.to_owned());
                                modify_online_machines = Some(&online_machines);
                                modify_offline_machines = None;
                            }

                            let activation = activation_time.unwrap().s.as_ref().unwrap().to_owned();
                            let activation_u64 = u64::from_str_radix(&activation, 36).unwrap();
                            let activation_modify_hash: Option<String>;
                            if activation_u64 == 0 {
                                let now_u64 = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
                                activation_modify_hash = Some(now_u64.to_string());
                            }else{
                                activation_modify_hash = None;
                            }
                            

                            let new_expiry: Option<i64>;
                            let new_expiry_string: Option<String>;
                            if expiration == 0 && (license_type.to_lowercase() == "trial" || license_type.to_lowercase() == "subscription" || license_type.to_lowercase() == "beta" ) {
                                let now =  SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
                                // error is right below vvv
                                let expiry_policy_found = plugin_item.get(&format!("{}PolicyExpirationDays", &license_type));
                                if expiry_policy_found.is_none() {
                                    return auto_response(true, 500, &format!("error 1828: {:?}", &license_type));
                                }
                                let expiry_days_result = expiry_policy_found.unwrap().n.as_ref().unwrap().parse::<u64>();
                                if expiry_days_result.is_err() {
                                    return auto_response(true, 500, &format!("Error 1832: {:?}", expiry_days_result.unwrap_err()));
                                }
                                let new_expiry_radix = now + (expiry_days_result.unwrap() * 86400);
                                // error above here
                                new_expiry_string = Some(format!("{:#}", radix_36(new_expiry_radix)));
                                new_expiry = Some(new_expiry_radix.to_i64().unwrap());
                            }else{
                                new_expiry = None;
                                new_expiry_string = None;
                            }
                            //return auto_response(true, 400, "eror");

                            let license_expr_attr_vals_result = modify_hashmap(
                                &license_data_whole, 
                                &license_data, 
                                &plugin, 
                                modify_online_machines, 
                                modify_offline_machines,
                                activation_modify_hash,
                                new_expiry_string
                            );

                            if license_expr_attr_vals_result.is_err() {
                                return auto_response(true, 500, &license_expr_attr_vals_result.unwrap_err().to_string());
                            }
                            let license_expr_attr_vals = license_expr_attr_vals_result.unwrap();


                            let mut plug_update_names: HashMap<String, String> = HashMap::new();
                            plug_update_names.insert("#a".to_owned(), "Calls".to_owned());
                            let mut plug_update_vals: HashMap<String, AttributeValue> = HashMap::new();
                            plug_update_vals.insert(":a".to_owned(),
                                AttributeValue {
                                    n: Some(1.to_string()),
                                    ..Default::default()
                            });

                            let plugin_transact_item = rusoto_dynamodb::TransactWriteItem {
                                update: Some(rusoto_dynamodb::Update {
                                    update_expression: "ADD #a :a".to_owned(),
                                    key: plugins_key_map.to_owned(),
                                    table_name: PLUGINS_TABLE_NAME.to_owned(),
                                    expression_attribute_names: Some(plug_update_names.to_owned()),
                                    expression_attribute_values: Some(plug_update_vals.to_owned()),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            };
                            let mut transact_items: Vec<rusoto_dynamodb::TransactWriteItem> = Vec::new();
                            transact_items.push(plugin_transact_item);
                            transact_items.push(rusoto_dynamodb::TransactWriteItem {
                                update: Some(rusoto_dynamodb::Update {
                                    update_expression: format!("SET {}", license_update_expr.join(",")),
                                    key: license_key_map.to_owned(),
                                    table_name: LICENSE_TABLE_NAME.to_owned(),
                                    expression_attribute_names: Some(license_expr_attr_names),
                                    expression_attribute_values: Some(license_expr_attr_vals),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            });

                            if user_transact_item.is_some() {
                                transact_items.push(user_transact_item.unwrap());
                            }

                            /*
                            if machine_exists {
                                if machine_update_item.is_some() {
                                    transact_items.push(
                                        rusoto_dynamodb::TransactWriteItem {
                                            update: Some(machine_update_item.unwrap()),
                                            ..Default::default()
                                        }
                                    );
                                }
                            }
                            */
                            return transact_write(
                                client,
                                transact_items.to_owned(), 
                                &company, 
                                messages.to_owned(),
                                messages_enabled.to_owned(),
                                messages_frequency.to_owned(),
                                &plugin, 
                                &mach, 
                                &mut cpu_stats, 
                                &mut instructions, 
                                &mut machine_list_item.to_owned(), 
                                &license_code, 
                                language_support.to_owned(), 
                                &plugin_item, 
                                license_data, 
                                &license_type, 
                                machines_allowed, 
                                initial_total_machines + 1, 
                                is_offline_license,
                                &message,
                                machine_exists,
                                new_expiry).await;                            
                        }

                        //let mut error_name = client_language.to_owned();
                        //error_name.push_str("OverMaxMachines");
                        let error_resp = language_support.get("OverMaxMachines").unwrap().s.as_ref().unwrap().to_owned();
                        let changed_resp = max_machines(&error_resp, &initial_total_machines);
                        return auto_response(true, 200, &changed_resp);
                        
                    }
                    //let mut error_name = client_language.to_owned();
                    //error_name.push_str("OverMaxMachines");
                    let error_resp = language_support.get("OverMaxMachines").unwrap().s.as_ref().unwrap().to_owned();
                    let changed_resp = max_machines(&error_resp, &initial_total_machines);
                    return auto_response(true, 200, &changed_resp);
                },
                None => {
                    return auto_response(true, 400, "Error L3: Client language configuration error.");
                }
            }
            //return auto_response(false, 200, plugins_item.unwrap()[0].get("EnglishTest").unwrap().s.as_ref().to_owned().unwrap());

            /*
        }
        _ => {
            return auto_response(true, 400, "Error I2: Invalid request.");
        }
    }
    */
    
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    run(service_fn(function_handler)).await?;
    
    Ok(())
}
