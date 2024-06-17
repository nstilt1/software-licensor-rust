use super::{GlobalSecondaryIndex, Item, MapItem, PrimaryHashKey};
use crate::dynamodb::maps_mk2::*;

pub struct LicensesTable {
    pub table_name: &'static str,
    /// primary index
    /// 
    /// created with hash(store_id + license_code)
    pub id: PrimaryHashKey<B>,
    /// The secondary index consists of a hash of the store ID and user id
    /// 
    /// created with hash(store_id + user_id)
    pub hashed_store_id_and_user_id: GlobalSecondaryIndex<B>,
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
    /// A map of strings of machine IDs that need to be deactivated. 
    /// 
    /// Vecs can contain duplicates and take O(n) lookup time
    pub machines_to_deactivate: Item<M>,
    /// The last time that a user attempted to regenerate their license code
    pub last_license_regen: Item<N>,
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
    id: PrimaryHashKey { item: Item::new("id") },
    protobuf_data: Item::new("data"),
    machines_to_deactivate: Item::new("deactivated_machs"),
    last_license_regen: Item::new("last_regen"),

    hashed_store_id_and_user_id: GlobalSecondaryIndex {
        index_name: "user_id_hash-index",
        item: Item::new("user_id_hash"),
    },

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