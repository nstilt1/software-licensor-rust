pub mod register_store_request;
pub mod register_store_response;
pub mod store_db_item;

pub mod create_product_request;
pub mod create_product_response;

pub mod create_license_request;
pub mod create_license_response;
//pub mod product_db_item;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "zeroize")]
use self::{
    create_product_request::{CreateProductRequest, ProductDbItem}, 
    create_product_response::CreateProductResponse, 
    create_license_request::{CreateLicenseRequest, LicenseDbItem},
    create_license_response::CreateLicenseResponse,
    register_store_request::RegisterStoreRequest, 
    register_store_response::RegisterStoreResponse, 
    store_db_item::StoreDbItem
};


// just some zeroize configuration for an attempt at anonymizing.

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

impl_zeroize_on_drop_for_struct!(
    RegisterStoreRequest, 
    contact_first_name,
    contact_last_name,
    contact_email,
    country,
    discord_username,
    store_name,
    store_url
);

impl_zeroize_on_drop_for_struct!(RegisterStoreResponse, store_id);

impl_zeroize_on_drop_for_struct!(
    StoreDbItem,
    contact_first_name,
    contact_last_name,
    country,
    discord_username,
    product_ids,
    store_name,
    store_url,
    email
);

impl_zeroize_on_drop_for_struct!(CreateProductRequest, product_name, version);
impl_zeroize_on_drop_for_struct!(CreateProductResponse, product_id);
impl_zeroize_on_drop_for_struct!(ProductDbItem, product_id, product_name, store_id, version);

impl_zeroize_on_drop_for_struct!(CreateLicenseRequest, customer_first_name, customer_last_name, customer_email, user_id);
impl_zeroize_on_drop_for_struct!(CreateLicenseResponse, license_code, offline_code);
impl_zeroize_on_drop_for_struct!(LicenseDbItem, license_id, customer_first_name, customer_last_name, customer_email, offline_secret);
