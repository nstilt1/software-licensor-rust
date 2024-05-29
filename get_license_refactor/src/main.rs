//! A plugin creation API method for a licensing service.

use std::collections::HashMap;
use utils::aws_config::meta::region::RegionProviderChain;
use utils::aws_sdk_dynamodb::Client;
use utils::aws_sdk_s3::primitives::Blob;
use utils::crypto::p384::ecdsa::Signature;
use utils::crypto::sha2::Sha384;
use utils::prelude::proto::protos::license_db_item::LicenseDbItem;
use utils::prelude::proto::protos::get_license_request::{GetLicenseRequest, GetLicenseResponse, LicenseInfo, Machine};
use utils::{debug_log, prelude::*};
use utils::tables::licenses::LICENSES_TABLE;
use utils::tables::stores::STORES_TABLE;
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use proto::prost::Message;
use http_private_key_manager::{Request as RestRequest, Response as RestResponse};

async fn process_request<D: Digest + FixedOutput>(key_manager: &mut KeyManager, request: &mut GetLicenseRequest, hasher: D, signature: Vec<u8>) -> Result<GetLicenseResponse, ApiError> {
    // the StoreId has already been verified in `decrypt_and_hash_request()` but
    // we still need to verify the signature against the public key in the db
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let aws_config = utils::aws_config::from_env().region(region_provider).load().await;
    let client = Client::new(&aws_config);
    
    let mut store_item = AttributeValueHashMap::new();
    let store_id = key_manager.get_store_id()?;
    let hashed_store_id = salty_hash(&[store_id.binary_id.as_ref()], &STORE_DB_SALT);
    store_item.insert_item(STORES_TABLE.id, Blob::new(hashed_store_id.to_vec()));

    let get_output = client.get_item()
        .table_name(STORES_TABLE.table_name)
        .set_key(Some(store_item))
        .consistent_read(false)
        .send()
        .await?;
    
    store_item = match get_output.item {
        Some(x) => x,
        // It is very unlikely that this will happen, unless the salt used for 
        // hashing were to change... in which case, it would happen every time
        None => return Err(ApiError::NotFound)
    };

    let public_key = store_item.get_item(STORES_TABLE.public_key)?;
    // verify signature with public key
    let pubkey = PublicKey::from_sec1_bytes(&public_key.as_ref())?;
    let verifier = VerifyingKey::from(pubkey);
    let signature: Signature = Signature::from_bytes(signature.as_slice().try_into().unwrap())?;
    verifier.verify_digest(hasher, &signature)?;

    // signature verified
    // get license item from db
    let mut license_item = AttributeValueHashMap::new();
    license_item.insert_item(
        LICENSES_TABLE.hashed_store_id_and_user_id, 
        Blob::new(salty_hash(&[store_id.binary_id.as_ref(), 
        request.user_id.as_bytes()], &LICENSE_DB_SALT).to_vec())
    );
    let get_output = client.get_item()
        .set_key(Some(license_item))
        .consistent_read(false)
        .send()
        .await?;
    
    license_item = match get_output.item {
        Some(x) => x,
        None => return Err(ApiError::NotFound)
    };
    
    let (license_code, offline_code) = {
        let license_protobuf: LicenseDbItem = key_manager.decrypt_db_proto(
            &LICENSES_TABLE.table_name, 
            license_item.get_item(LICENSES_TABLE.id)?.as_ref(),
            license_item.get_item(LICENSES_TABLE.protobuf_data)?.as_ref()
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
    };

    Ok(response)
}

async fn handle_crypto(key_manager: &mut KeyManager, request: &mut RestRequest, req_bytes: &[u8], is_handshake: bool, chosen_symmetric_algorithm: &str, signature: Vec<u8>) -> Result<(RestResponse, Signature), ApiError> {
    type Req = GetLicenseRequest;
    type Resp = GetLicenseResponse;
    match chosen_symmetric_algorithm {
        "chacha20poly1305" => {
            let (mut decrypted, hash) = {
                debug_log!("In chacha20poly1305 segment");
                let result = key_manager.decrypt_and_hash_request::<ChaCha20Poly1305, Sha384, Req>(request, req_bytes, is_handshake);
                debug_log!("Got result in chacha20poly1305 segment");
                result.unwrap()
            };
            debug_log!("Sending result to process_request()");
            let mut response = process_request(key_manager, &mut decrypted, hash, signature).await?;
            debug_log!("Encrypting and signing the response");
            Ok(key_manager.encrypt_and_sign_response::<ChaCha20Poly1305, Resp>(&mut response)?)
        },
        "aes-gcm-128" => {
            debug_log!("In aes-gcm-128 segment");
            let (mut decrypted, hash) = key_manager.decrypt_and_hash_request::<Aes128Gcm, Sha384, Req>(request, req_bytes, is_handshake)?;
            let mut response = process_request(key_manager, &mut decrypted, hash, signature).await?;
            Ok(key_manager.encrypt_and_sign_response::<Aes128Gcm, Resp>(&mut response)?)
        },
        "aes-gcm-256" => {
            debug_log!("In aes-gcm-256 segment");
            let (mut decrypted, hash) = key_manager.decrypt_and_hash_request::<Aes256Gcm, Sha384, Req>(request, req_bytes, is_handshake)?;
            let mut response = process_request(key_manager, &mut decrypted, hash, signature).await?;
            Ok(key_manager.encrypt_and_sign_response::<Aes256Gcm, Resp>(&mut response)?)
        }
        _ => {
            debug_log!("Invalid symmetric encryption algorithm error");
            return Err(ApiError::InvalidRequest("Invalid symmetric encryption algorithm".into()))
        }
    }
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
    let crypto_result = handle_crypto(&mut key_manager, &mut request, req_bytes, false, &chosen_symm_algo, signature).await;
    
    let (encrypted, signature) = if let Ok(v) = crypto_result {
        v
    } else {
        return crypto_result.unwrap_err().respond()
    };

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
