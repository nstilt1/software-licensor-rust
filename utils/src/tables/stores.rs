//! Some constants for the Stores Table
use super::{Item, PrimaryHashKey};
use crate::dynamodb::maps_mk2::*;

pub struct StoresTable {
    pub table_name: &'static str,
    /// primary index
    pub id: PrimaryHashKey<B>,
    /// this hashed email will be a secondary index
    pub email: Item<B>,
    pub protobuf_data: Item<B>,
    pub public_key: Item<B>,
    pub registration_date: Item<N>,
}

pub const STORES_TABLE: StoresTable = StoresTable {
    table_name: STORES_TABLE_NAME,
    id: PrimaryHashKey { item: Item::new("id") },
    email: Item::new("email"),
    protobuf_data: Item::new("data"),
    public_key: Item::new("pubkey"),
    registration_date: Item::new("registration_date"),
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