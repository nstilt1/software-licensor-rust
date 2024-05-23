// This file is @generated by prost-build.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LicenseActivationRequest {
    /// the license code. should look like:
    /// 1234-5678-90ab-cdef-1234
    /// or caps or with an offline code:
    /// 1234-5678-90ab-cdef-1234-offline-abcd
    #[prost(string, tag = "1")]
    pub license_code: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub machine_id: ::prost::alloc::string::String,
    /// this language_id can be used to have the server send a response in
    /// a pre-determined language
    #[prost(string, tag = "3")]
    pub language_id: ::prost::alloc::string::String,
    /// hardware/simd statistics
    #[prost(message, optional, tag = "4")]
    pub hardware_stats: ::core::option::Option<Stats>,
    #[prost(string, tag = "5")]
    pub product_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "50")]
    pub timestamp: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Stats {
    #[prost(string, tag = "1")]
    pub os_name: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub computer_name: ::prost::alloc::string::String,
    #[prost(bool, tag = "3")]
    pub is_64_bit: bool,
    #[prost(string, tag = "4")]
    pub users_language: ::prost::alloc::string::String,
    #[prost(string, tag = "5")]
    pub display_language: ::prost::alloc::string::String,
    #[prost(uint32, tag = "6")]
    pub num_logical_cores: u32,
    #[prost(uint32, tag = "7")]
    pub num_physical_cores: u32,
    #[prost(uint32, tag = "8")]
    pub cpu_freq_mhz: u32,
    #[prost(uint32, tag = "34")]
    pub ram_mb: u32,
    #[prost(uint32, tag = "35")]
    pub page_size: u32,
    #[prost(string, tag = "9")]
    pub cpu_vendor: ::prost::alloc::string::String,
    #[prost(string, tag = "10")]
    pub cpu_model: ::prost::alloc::string::String,
    #[prost(bool, tag = "11")]
    pub has_mmx: bool,
    #[prost(bool, tag = "12")]
    pub has_3d_now: bool,
    #[prost(bool, tag = "13")]
    pub has_fma3: bool,
    #[prost(bool, tag = "14")]
    pub has_fma4: bool,
    #[prost(bool, tag = "15")]
    pub has_sse: bool,
    #[prost(bool, tag = "16")]
    pub has_sse2: bool,
    #[prost(bool, tag = "17")]
    pub has_sse3: bool,
    #[prost(bool, tag = "18")]
    pub has_ssse3: bool,
    #[prost(bool, tag = "19")]
    pub has_sse41: bool,
    #[prost(bool, tag = "20")]
    pub has_sse42: bool,
    #[prost(bool, tag = "21")]
    pub has_avx: bool,
    #[prost(bool, tag = "22")]
    pub has_avx2: bool,
    #[prost(bool, tag = "23")]
    pub has_avx512f: bool,
    #[prost(bool, tag = "24")]
    pub has_avx512bw: bool,
    #[prost(bool, tag = "25")]
    pub has_avx512cd: bool,
    #[prost(bool, tag = "26")]
    pub has_avx512dq: bool,
    #[prost(bool, tag = "27")]
    pub has_avx512er: bool,
    #[prost(bool, tag = "28")]
    pub has_avx512ifma: bool,
    #[prost(bool, tag = "29")]
    pub has_avx512pf: bool,
    #[prost(bool, tag = "30")]
    pub has_avx512vbmi: bool,
    #[prost(bool, tag = "31")]
    pub has_avx512vl: bool,
    #[prost(bool, tag = "32")]
    pub has_avx512vpopcntdq: bool,
    #[prost(bool, tag = "33")]
    pub has_neon: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LicenseKeyFile {
    #[prost(string, tag = "1")]
    pub product_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub customer_first_name: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub customer_last_name: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub product_version: ::prost::alloc::string::String,
    #[prost(string, tag = "10")]
    pub license_code: ::prost::alloc::string::String,
    #[prost(string, tag = "11")]
    pub license_type: ::prost::alloc::string::String,
    #[prost(string, tag = "20")]
    pub machine_id: ::prost::alloc::string::String,
    #[prost(uint64, tag = "21")]
    pub timestamp: u64,
    /// determines when the license expires or needs to be renewed
    #[prost(uint64, optional, tag = "25")]
    pub expiration_timestamp: ::core::option::Option<u64>,
    /// determines when the client should attempt to renew the license
    /// expiration. Useful for allowing users to deactivate their machines
    /// that they've stopped using
    /// It is also useful for subscriptions and trials automatically renewing
    /// the expiration
    #[prost(uint64, optional, tag = "26")]
    pub check_back_timestamp: ::core::option::Option<u64>,
    #[prost(string, tag = "30")]
    pub message: ::prost::alloc::string::String,
    /// a response code; valid codes are
    /// 1: success
    /// 2: no license found
    /// 4: reached the machine limit
    /// 8: trial ended
    /// 16: license no longer active
    /// 32: incorrect offline code
    /// 64: Offline codes are not allowed for this product
    #[prost(uint32, tag = "31")]
    pub message_code: u32,
    /// the message to show if the license ever expires on the user
    #[prost(string, tag = "35")]
    pub post_expiration_message: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LicenseActivationResponse {
    #[prost(message, optional, tag = "1")]
    pub key_file: ::core::option::Option<LicenseKeyFile>,
    #[prost(bytes = "vec", tag = "2")]
    pub key_file_signature: ::prost::alloc::vec::Vec<u8>,
}