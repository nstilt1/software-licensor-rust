use utils::prelude::proto::{prost::Message, protos};


pub fn generate_create_product_payload() -> Vec<u8> {
    use protos::create_product_request::CreateProductRequest;
    let req = CreateProductRequest {
        version: "0.0".into(),
        product_name: "Test product".into(),
        product_id_prefix: "Test".into(),
        is_offline_allowed: false,
        max_machines_per_license: 3,
    };
    req.encode_length_delimited_to_vec()
}