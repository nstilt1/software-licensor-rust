pub mod register_store_request;
pub mod register_store_response;
pub mod store_db_item;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use self::{
    register_store_request::RegisterStoreRequest, 
    register_store_response::RegisterStoreResponse,
    store_db_item::StoreDbItem,
};


// just some zeroize configuration for an attempt at anonymizing.
// they would have been overwritten if I place these in the other directories
#[cfg(feature = "zeroize")]
impl Drop for RegisterStoreRequest {
    fn drop(&mut self) {
        self.contact_first_name.zeroize();
        self.contact_last_name.zeroize();
        self.country.zeroize();
        self.discord_username.zeroize();
        self.store_name.zeroize();
        self.store_url.zeroize();
        self.contact_email.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for RegisterStoreRequest {}

#[cfg(feature = "zeroize")]
impl Drop for RegisterStoreResponse {
    fn drop(&mut self) {
        self.store_id.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for RegisterStoreResponse {}

#[cfg(feature = "zeroize")]
impl Drop for StoreDbItem {
    fn drop(&mut self) {
        self.contact_first_name.zeroize();
        self.contact_last_name.zeroize();
        self.country.zeroize();
        self.discord_username.zeroize();
        self.product_ids.zeroize();
        self.store_name.zeroize();
        self.store_url.zeroize();
        self.email.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for StoreDbItem {}