// This file is @generated by prost-build.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LinkStoreRequest {
    #[prost(string, tag = "1")]
    pub store_id: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct LinkStoreResponse {
    #[prost(message, optional, tag = "2")]
    pub store_metrics: ::core::option::Option<Metrics>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct Metrics {
    #[prost(uint32, tag = "1")]
    pub num_products: u32,
    #[prost(uint32, tag = "2")]
    pub num_licenses: u32,
    #[prost(uint32, tag = "3")]
    pub num_licensed_machines: u32,
    /// if greater than 0, they could be crackers since offline activations are
    /// probably disabled
    #[prost(uint32, tag = "4")]
    pub num_offline_machines: u32,
    /// the total number of online-registered machines; there may be some overlap
    /// based on num_license_regens
    #[prost(uint32, tag = "5")]
    pub num_online_machines: u32,
    #[prost(uint32, tag = "10")]
    pub num_license_activations: u32,
    #[prost(uint32, tag = "15")]
    pub num_license_regens: u32,
    /// if greater than 0, they could be legit hackers
    #[prost(uint32, tag = "20")]
    pub num_machine_deactivations: u32,
}
