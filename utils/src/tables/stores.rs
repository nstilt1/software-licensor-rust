//! Some constants for the Stores Table
use super::Item;
use crate::dynamodb::maps_mk2::*;

pub struct StoresTable {
    pub table_name: &'static str,
    /// primary index
    pub id: Item<B>,
    /// this hashed email will be a secondary index
    pub email: Item<B>,
    pub protobuf_data: Item<B>,
    pub public_key: Item<B>,
    pub registration_date: Item<N>,
    /// The amount of times that `create_plugin` has been called
    pub num_products: Item<N>,
    /// The amount of times `create_license` has been called
    pub num_licenses: Item<N>,
    /// The amount of times `license_auth` has been called
    pub num_auths: Item<N>,
    /// The amount of times that a user's license code has been regenerated
    pub num_license_regens: Item<N>,
}

pub const STORES_TABLE: StoresTable = StoresTable {
    table_name: STORES_TABLE_NAME,
    id: Item::new("hashed_id"),
    email: Item::new("hashed_email"),
    protobuf_data: Item::new("DATA"),
    public_key: Item::new("PUBKEY"),
    registration_date: Item::new("REGISTRATION_DATE"),
    num_products: Item::new("NUM_PLUGINS"),
    num_licenses: Item::new("NUM_LICENSES"),
    num_auths: Item::new("NUM_AUTHS"),
    num_license_regens: Item::new("NUM_LICENSE_REGENS"),
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