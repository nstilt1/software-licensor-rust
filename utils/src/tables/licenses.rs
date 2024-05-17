use super::{Item, MapItem};
use crate::dynamodb::maps_mk2::*;

pub struct LicensesTable {
    pub table_name: &'static str,
    /// primary index
    /// 
    /// created with hash(store_id + license_code)
    pub id: Item<B>,
    /// this hashed store ID will be a secondary index
    /// 
    /// created with hash(store_id + user_id)
    pub hashed_store_id_and_user_id: Item<B>,
    pub order_id: Item<S>,
    pub custom_success_message: Item<S>,
    /// a hashed email address for doing some analytics, such as seeing
    /// what percentage of users own a license for a particular product
    /// 
    /// if not provided, it will be all 0s
    pub email_hash: Item<B>,
    pub plugins_map_item: MapItem<PluginsMap>,
    pub protobuf_data: Item<B>,
}

pub struct PluginsMap {
    pub hashed_plugin_id: Item<B>,
    pub activation_time: Item<N>,
    pub license_type: Item<S>,
    pub expiry_time: Item<S>,
    pub is_license_active: Item<Bool>,
    pub machines_allowed: Item<N>,
    pub offline_machines: Item<SS>,
    pub online_machines: Item<SS>,
    pub order_ids: Item<SS>,
    pub is_subscription_active: Item<Bool>
}

pub const LICENSES_TABLE: LicensesTable = LicensesTable {
    table_name: "PRODUCTS-BMEvbp9AszCuk5pZg_yt6f_rinRsdIycprMMcNzMYkljl94EPpstEfjr",
    id: Item::new("hashed_id"),
    protobuf_data: Item::new("data"),
    hashed_store_id_and_user_id: Item::new("user_id_hash"),
    order_id: Item::new("order_id"),
    custom_success_message: Item::new("custom_message"),
    email_hash: Item::new("email_hash"),
    plugins_map_item: MapItem::<PluginsMap> {
        key: Item::new("plugin_map"),
        fields: PluginsMap { 
            hashed_plugin_id: Item::new("plugin_id"), 
            activation_time: Item::new("activation_time"), 
            license_type: Item::new("license_type"), 
            expiry_time: Item::new("expiry_time"), 
            is_license_active: Item::new("is_license_active"), 
            machines_allowed: Item::new("max_machines"), 
            offline_machines: Item::new("offline_machines"), 
            online_machines: Item::new("online_machines"), 
            order_ids: Item::new("order_ids"), 
            is_subscription_active: Item::new("is_subscription_active") 
        },
    },
};