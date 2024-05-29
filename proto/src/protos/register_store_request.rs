// This file is @generated by prost-build.
/// A store registration request
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterStoreRequest {
    #[prost(string, tag = "1")]
    pub contact_first_name: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub contact_last_name: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub contact_email: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub store_name: ::prost::alloc::string::String,
    #[prost(string, tag = "6")]
    pub store_url: ::prost::alloc::string::String,
    #[prost(string, tag = "10")]
    pub discord_username: ::prost::alloc::string::String,
    #[prost(string, tag = "27")]
    pub state: ::prost::alloc::string::String,
    #[prost(string, tag = "29")]
    pub country: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "30")]
    pub public_signing_key: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "35")]
    pub configs: ::core::option::Option<Configs>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Configs {
    #[prost(uint32, tag = "60")]
    pub max_machines_per_license: u32,
    /// some notes about "frequency" and "expiration":
    ///
    /// the frequency dictates the minimum amount of time that must pass before a
    /// client will reconnect with the server to check on the status of their
    /// license(s). This is important in case the user tries to remove a machine
    /// from their license, or if they were to refund their license purchase
    ///
    /// the expiration dictates how long the client will be able to go without
    /// contacting the server. The expiration is important in the event that a
    /// user were to deactivate a computer on their license, and if the
    /// "deactivated" client never reached back out to the server to find out
    /// that it is supposed to be deactivated
    #[prost(uint32, tag = "70")]
    pub offline_license_frequency_hours: u32,
    #[prost(uint32, tag = "80")]
    pub perpetual_license_expiration_days: u32,
    #[prost(uint32, tag = "90")]
    pub perpetual_license_frequency_hours: u32,
    #[prost(uint32, tag = "100")]
    pub subscription_license_expiration_days: u32,
    /// these "leniency hours" get added onto the expiration date in case there's
    /// a niche timing unalignment with any communicating servers, such as the
    /// payment processor processing the subscription payment that has to be
    /// hooked from the store's backend that has to send a request to the
    /// licensing
    #[prost(uint32, tag = "110")]
    pub subscription_license_expiration_leniency_hours: u32,
    #[prost(uint32, tag = "120")]
    pub subscription_license_frequency_hours: u32,
    #[prost(uint32, tag = "130")]
    pub trial_license_expiration_days: u32,
    #[prost(uint32, tag = "140")]
    pub trial_license_frequency_hours: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterStoreResponse {
    #[prost(string, tag = "1")]
    pub store_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "10")]
    pub timestamp: u64,
}
