// This file is @generated by prost-build.
/// store registration response
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterStoreResponse {
    #[prost(string, tag = "1")]
    pub store_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "10")]
    pub timestamp: u64,
}
