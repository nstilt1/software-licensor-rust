//! A plugin creation API method for a licensing service.

use std::collections::HashMap;
use utils::prelude::proto::protos::license_db_item::LicenseDbItem;
use utils::prelude::proto::protos::get_license_request::{GetLicenseRequest, GetLicenseResponse, LicenseInfo, Machine};
use utils::{now_as_seconds, prelude::*};
use utils::tables::licenses::LICENSES_TABLE;
use utils::tables::stores::STORES_TABLE;
use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDbClient, DynamoDb, GetItemInput};
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use proto::prost::Message;
use http_private_key_manager::Request as RestRequest;

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut GetLicenseRequest, hasher: D, signature: Vec<u8>) -> Result<GetLicenseResponse, ApiError> {
    // the StoreId has already been verified in `decrypt_and_hash_request()` but
    // we still need to verify the signature against the public key in the db
    let client = DynamoDbClient::new(Region::UsEast1);
    let mut store_item = AttributeValueHashMap::new();
    let store_id = key_manager.get_store_id()?;
    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], STORE_DB_SALT);
    store_item.insert_item_into(STORES_TABLE.id, hashed_store_id.to_vec());

    let get_output = client.get_item(
        GetItemInput {
            table_name: STORES_TABLE.table_name.to_string(),
            key: store_item,
            consistent_read: Some(false),
            ..Default::default()
        }
    ).await?;
    
    store_item = match get_output.item {
        Some(x) => x,
        // It is very unlikely that this will happen, unless the salt used for 
        // hashing were to change... in which case, it would happen every time
        None => return Err(ApiError::NotFound)
    };

    let public_key = store_item.get_item(STORES_TABLE.public_key)?;
    // verify signature with public key
    let pubkey = PublicKey::from_sec1_bytes(&public_key)?;
    let verifier = VerifyingKey::from(pubkey);
    let signature = DerSignature::try_from(signature.as_slice())?;
    verifier.verify_digest(hasher, &signature)?;

    // signature verified
    // get license item from db
    let mut license_item = AttributeValueHashMap::new();
    license_item.insert_item_into(
        LICENSES_TABLE.hashed_store_id_and_user_id, 
        salty_hash(&[store_id.binary_id.as_ref(), 
        request.user_id.as_bytes()], LICENSE_DB_SALT).to_vec()
    );
    let get_output = client.get_item(GetItemInput {
        key: license_item,
        consistent_read: Some(false),
        ..Default::default()
    }).await?;
    
    license_item = match get_output.item {
        Some(x) => x,
        None => return Err(ApiError::NotFound)
    };
    
    let (license_code, offline_code) = {
        let license_protobuf: LicenseDbItem = key_manager.decrypt_db_proto(
            &LICENSES_TABLE.table_name, 
            license_item.get_item(LICENSES_TABLE.id)?,
            license_item.get_item(LICENSES_TABLE.protobuf_data)?
        )?;
        let license_code = bytes_to_license(&license_protobuf.license_id);
        (license_code, license_protobuf.offline_secret.to_string())
    };
    
    let mut licensed_products: HashMap<String, LicenseInfo> = HashMap::new();
    let products_map = license_item.get_item(LICENSES_TABLE.products_map_item.key)?;
    for key in products_map.keys() {
        let product = products_map.get_map_by_str(key.as_str())?;
        let offline_machines_map = product.get_item(LICENSES_TABLE.products_map_item.fields.offline_machines.key)?;
        let online_machines_map = product.get_item(LICENSES_TABLE.products_map_item.fields.online_machines.key)?;
        let machine_limit = product.get_item(LICENSES_TABLE.products_map_item.fields.machines_allowed)?.parse::<u32>()?;
        
        let mut offline_machines: Vec<Machine> = Vec::with_capacity(offline_machines_map.len());
        let mut online_machines: Vec<Machine> = Vec::with_capacity(online_machines_map.len());
        
        let workspace = &mut [(offline_machines_map, &mut offline_machines), (online_machines_map, &mut online_machines)];
        for (map, vec) in workspace.iter_mut() {
            for k in map.keys() {
                let id = k;
                let machine = map.get_map_by_str(k)?;
                let os = machine.get_item(LICENSES_TABLE.products_map_item.fields.offline_machines.fields.os_name)?;
                let computer_name = machine.get_item(LICENSES_TABLE.products_map_item.fields.offline_machines.fields.computer_name)?;
                vec.push(Machine { 
                    id: id.to_string(), 
                    os: os.to_string(), 
                    computer_name: computer_name.to_string() 
                });
            }
        }
        licensed_products.insert(key.to_string(), LicenseInfo {
            offline_machines, online_machines, machine_limit
        });
    }
    let response = GetLicenseResponse {
        licensed_products,
        license_code,
        offline_code,
        timestamp: now_as_seconds(),
    };

    Ok(response)
}
/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    // Extract some useful information from the request
    if event.query_string_parameters_ref().is_some() {
        return ApiError::InvalidRequest("There should be no query string parameters.".into()).respond();
    }
    let signature = if let Some(s) = event.headers().get("X-Signature") {
        s.as_bytes().from_base64()?
    } else {
        return Err(Box::new(ApiError::InvalidRequest("Signature must be base64 encoded in the X-Signature header".into())))
    };
    let (mut request, req_bytes) = if let Body::Binary(contents) = event.body() {
        (RestRequest::decode(contents.as_slice())?, contents)
    } else {
        return ApiError::InvalidRequest("Body is not binary".into()).respond()
    };

    let mut key_manager = init_key_manager(None, None);

    let chosen_symm_algo = request.symmetric_algorithm.to_lowercase();
    let (encrypted, signature) = process_request_with_symmetric_algorithm!(
        key_manager, 
        process_request,
        &mut request,
        req_bytes,
        GetLicenseRequest,
        GetLicenseResponse,
        sha2::Sha384,
        signature,
        chosen_symm_algo.as_str(),
        false,                     // is_handshake    
        // the following values allow the client to choose the symmetric encryption algorithm via the `symmetric_algorithm` field in the request's protobuf message
        ("chacha20poly1305", ChaCha20Poly1305),
        ("aes-gcm-128", Aes128Gcm),
        ("aes-gcm-siv-128", Aes128GcmSiv),
        ("aes-gcm-256", Aes256Gcm),
        ("aes-gcm-siv-256", Aes256GcmSiv)
    );

    // package `encrypted` into a response and `signature` into the header

    // Return something that implements IntoResponse.
    // It will be serialized to the right response event automatically by the runtime

    let resp = Response::builder()
        .status(200)
        .header("content-type", "application/x-protobuf")
        .header("X-Signature-Info", "Algorithm: Sha2-384 + NIST-P384")
        .header("X-Signature", signature.to_bytes().as_slice().to_base64())
        .body(encrypted.encode_to_vec().into())
        .map_err(Box::new)?;

    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}
