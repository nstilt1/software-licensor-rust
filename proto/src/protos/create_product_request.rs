// This file is @generated by prost-build.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateProductRequest {
    #[prost(string, tag = "1")]
    pub version: ::prost::alloc::string::String,
    #[prost(string, tag = "20")]
    pub product_name: ::prost::alloc::string::String,
    #[prost(string, tag = "21")]
    pub product_id_prefix: ::prost::alloc::string::String,
    #[prost(bool, tag = "40")]
    pub is_offline_allowed: bool,
    #[prost(uint32, tag = "60")]
    pub max_machines_per_license: u32,
    #[prost(uint64, tag = "150")]
    pub timestamp: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateProductResponse {
    /// the product id that you will need to specify in the license_auth
    /// request
    #[prost(string, tag = "1")]
    pub product_id: ::prost::alloc::string::String,
    /// the public verifying key for this product. You will need to verify
    /// the server's signature on the key file with this public key.
    #[prost(bytes = "vec", tag = "2")]
    pub product_public_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "10")]
    pub timestamp: u64,
}
