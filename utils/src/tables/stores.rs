//! Some constants for the Stores Table
use super::Item;
use crate::dynamodb::maps_mk2::*;

pub struct StoresTable {
    pub table_name: &'static str,
    pub id: Item<B>,
    pub protobuf_data: Item<B>,
    pub public_key: Item<B>,
    pub registration_date: Item<N>,
    /// The amount of times that `create_plugin` has been called
    pub num_products: Item<N>,
    /// The amount of times `create_license` has been called
    pub num_licenses: Item<N>,
    /// The amount of times `license_auth` has been called
    pub num_auths: Item<N>,
}

pub const STORES_TABLE: StoresTable = StoresTable {
    table_name: STORES_TABLE_NAME,
    id: Item { key: "ID", ty: B},
    protobuf_data: Item { key: "DATA", ty: B},
    public_key: Item { key: "PUBKEY", ty: B},
    registration_date: Item { key: "REGISTRATION_DATE", ty: N},
    num_products: Item { key: "NUM_PLUGINS", ty: N },
    num_licenses: Item { key: "NUM_LICENSES", ty: N },
    num_auths: Item { key: "NUM_AUTHS", ty: N },
};

pub const STORES_TABLE_NAME: &str = "STORES-eS-GT7oDw5AZQuRqzf-g5t2SN8nGwKv-q4q0amq7o4CW9Ko4bXk1YLEKvX";

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lifetime(str: &str) {
        println!("{}", str)
    }

    /// Making sure we don't have to deal with lifetimes when accessing values
    #[test]
    fn lifetimes() {
        test_lifetime(&STORES_TABLE.protobuf_data.key);
    }
}