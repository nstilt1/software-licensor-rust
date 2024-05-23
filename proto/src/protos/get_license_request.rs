// This file is @generated by prost-build.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetLicenseRequest {
    #[prost(string, tag = "1")]
    pub user_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "20")]
    pub timestamp: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetLicenseResponse {
    /// a map of product_ids to license info
    #[prost(map = "string, message", tag = "1")]
    pub licensed_products: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        LicenseInfo,
    >,
    #[prost(string, tag = "2")]
    pub license_code: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub offline_code: ::prost::alloc::string::String,
    #[prost(uint64, tag = "20")]
    pub timestamp: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LicenseInfo {
    #[prost(message, repeated, tag = "1")]
    pub offline_machines: ::prost::alloc::vec::Vec<Machine>,
    #[prost(message, repeated, tag = "2")]
    pub online_machines: ::prost::alloc::vec::Vec<Machine>,
    #[prost(uint32, tag = "3")]
    pub machine_limit: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Machine {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub os: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub computer_name: ::prost::alloc::string::String,
}