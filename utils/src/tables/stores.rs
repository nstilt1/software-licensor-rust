//! Some constants for the Stores Table
use super::Item;

pub struct StoresTable {
    pub table_name: &'static str,
    pub id: Item,
    pub protobuf_data: Item,
    pub public_key: Item,
    pub registration_date: Item,
    /// The amount of times that `create_plugin` has been called
    pub num_products: Item,
    /// The amount of times `create_license` has been called
    pub num_licenses: Item,
    /// The amount of times `license_auth` has been called
    pub num_auths: Item,
}
use items::*;

pub const STORES_TABLE: StoresTable = StoresTable {
    table_name: STORES_TABLE_NAME,
    id: ID,
    protobuf_data: PROTOBUF_DATA,
    public_key: PUBLIC_KEY,
    registration_date: REGISTRATION_DATE,
    num_products: Item { key: "NUM_PLUGINS", ty: "N" },
    num_licenses: Item { key: "NUM_LICENSES", ty: "N" },
    num_auths: Item { key: "NUM_AUTHS", ty: "N" },
};

pub const STORES_TABLE_NAME: &str = "STORES-eS-GT7oDw5AZQuRqzf-g5t2SN8nGwKv-q4q0amq7o4CW9Ko4bXk1YLEKvX";

/// A module with consts in case this is a better way to access item keys
pub mod items {
    use super::Item;
    pub const ID: Item = Item { key: "ID", ty: "B" };
    pub const PROTOBUF_DATA: Item = Item {key: "DATA", ty: "B"};
    pub const PUBLIC_KEY: Item = Item {key: "PUBKEY", ty: "B"};
    pub const REGISTRATION_DATE: Item = Item {key: "REGISTRATION_TIME", ty: "N"};
    pub const METRICS: Item = Item {key: "METRICS", ty: "M"};
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lifetime(str: &str) {
        println!("{}", str)
    }

    /// Making sure we don't have to deal with lifetimes when accessing values
    #[test]
    fn lifetimes() {
        test_lifetime(&PROTOBUF_DATA.key);
        test_lifetime(&STORES_TABLE.protobuf_data.key);
    }
}