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
    pub custom_success_message: Item<S>,
    /// a hashed email address for doing some analytics, such as seeing
    /// what percentage of users own a license for a particular product
    /// 
    /// if not provided, it will be all 0s
    pub email_hash: Item<B>,
    pub products_map_item: MapItem<ProductsMap>,
    /// * license_id binary
    /// * customer_first_name
    /// * customer_email
    /// * offline_secret
    pub protobuf_data: Item<B>,
}

pub struct ProductsMap {
    pub activation_time: Item<N>,
    pub license_type: Item<S>,
    pub expiry_time: Item<N>,
    pub is_license_active: Item<Bool>,
    pub machines_allowed: Item<N>,
    pub offline_machines: MapItem<MachineMap>,
    pub online_machines: MapItem<MachineMap>,
    pub is_subscription_active: Item<Bool>
}

pub struct MachineMap {
    pub os_name: Item<S>,
    pub computer_name: Item<S>
}

pub const MACHINE: MachineMap = MachineMap {
    os_name: Item::new("os"),
    computer_name: Item::new("name"),
};

pub const LICENSES_TABLE: LicensesTable = LicensesTable {
    table_name: "LICENSES-AgKSHjwfYk0lu-s-a2nvizD-DgUP5ORzOO_ZQRajJ12z2nxBs1kvMTse",
    id: Item::new("hashed_id"),
    protobuf_data: Item::new("data"),
    hashed_store_id_and_user_id: Item::new("user_id_hash"),
    custom_success_message: Item::new("custom_message"),
    email_hash: Item::new("email_hash"),
    products_map_item: MapItem::<ProductsMap> {
        key: Item::new("products_map"),
        fields: ProductsMap { 
            activation_time: Item::new("activation_time"), 
            license_type: Item::new("license_type"), 
            expiry_time: Item::new("expiry_time"), 
            is_license_active: Item::new("is_license_active"), 
            machines_allowed: Item::new("max_machines"), 
            offline_machines: MapItem::<MachineMap> { 
                key: Item::new("offline_machines"), 
                fields: MACHINE 
            }, 
            online_machines: MapItem::<MachineMap> {
                key: Item::new("online_machines"),
                fields: MACHINE
            }, 
            is_subscription_active: Item::new("is_subscription_active") 
        },
    },
};