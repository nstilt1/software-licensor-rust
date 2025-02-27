pub mod pubkeys;

pub mod request;
pub mod response;

pub mod register_store_request;

pub mod create_product_request;
pub mod product_db_item;

pub mod create_license_request;
pub mod license_db_item;

pub mod license_activation_request;

pub mod get_license_request;

pub mod deactivate_machines;

pub mod regenerate_license_code;

pub mod create_store_request;

pub mod get_metrics_request;

pub mod link_store_request;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "zeroize")]
use self::{
    create_product_request::{CreateProductRequest, CreateProductResponse}, 
    create_license_request::CreateLicenseRequest,
    register_store_request::RegisterStoreResponse, 
    create_store_request::{StoreDbItem, UpdateSettingsRequest},
    license_db_item::LicenseDbItem,
    product_db_item::ProductDbItem,
    license_activation_request::{LicenseActivationRequest, Stats, LicenseKeyFile},
    get_license_request::{GetLicenseRequest, GetLicenseResponse},
    license_activation_request::LicenseActivationResponse
};


// just some zeroize configuration for an attempt at anonymizing. It probably
// is not necessary, and I might be missing a few spots.

/// Impls `ZeroizeOnDrop` for a struct with fields that impl Zeroize
/// 
/// # Usage
/// 
/// Just specify the struct and list the fields that need to be zeroized
macro_rules! impl_zeroize_on_drop_for_struct {
    ($proto:ident, $($field_to_zeroize:ident),*) => { 
        #[cfg(feature = "zeroize")]
        impl Drop for $proto {
            fn drop(&mut self) {
                $(
                    self.$field_to_zeroize.zeroize();
                )*
            }
        }
        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $proto {}
    };
}

impl_zeroize_on_drop_for_struct!(UpdateSettingsRequest, store_id);
impl_zeroize_on_drop_for_struct!(RegisterStoreResponse, store_id);

impl_zeroize_on_drop_for_struct!(
    StoreDbItem,
    contact_first_name,
    contact_last_name,
    country,
    discord_username,
    store_name,
    store_url,
    email
);

impl_zeroize_on_drop_for_struct!(CreateProductRequest, product_name, version);
impl_zeroize_on_drop_for_struct!(CreateProductResponse, product_id);
impl_zeroize_on_drop_for_struct!(ProductDbItem, product_id, product_name, store_id, version);

impl_zeroize_on_drop_for_struct!(CreateLicenseRequest, customer_first_name, customer_last_name, customer_email, user_id);
impl_zeroize_on_drop_for_struct!(LicenseDbItem, license_id, customer_first_name, customer_last_name, customer_email, offline_secret);

impl_zeroize_on_drop_for_struct!(LicenseActivationRequest, license_code, machine_id, product_ids);
impl_zeroize_on_drop_for_struct!(Stats, computer_name);
impl_zeroize_on_drop_for_struct!(LicenseKeyFile, machine_id, license_code);
impl_zeroize_on_drop_for_struct!(LicenseActivationResponse, customer_email, customer_first_name, customer_last_name);

impl_zeroize_on_drop_for_struct!(GetLicenseRequest, user_id);
impl_zeroize_on_drop_for_struct!(GetLicenseResponse, license_code, offline_code);