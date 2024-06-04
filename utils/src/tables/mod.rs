//! Module containing database table information, including:
//! * table names
//! * table layout
//! * item names

use std::marker::PhantomData;

use crate::prelude::{AttrValAbstraction, M};

pub mod stores;
pub mod products;
pub mod licenses;
pub mod machines;

pub struct Item<T: AttrValAbstraction> {
    pub key: &'static str,
    pub ty: PhantomData<T>
}

impl<T: AttrValAbstraction> Item<T> {
    pub const fn new(key: &'static str) -> Self {
        Self { key, ty: PhantomData}
    }
}

pub struct MapItem<F> {
    pub key: Item<M>,
    pub fields: F
}

pub struct GlobalSecondaryIndex<T: AttrValAbstraction> {
    pub index_name: &'static str,
    pub item: Item<T>
}

#[cfg(test)]
mod generating_ids {
    use super::super::crypto::*;
    use http_private_key_manager::prelude::*;
    type TableName = BinaryId<U48, U8, 16, use_timestamps::Never>;

    fn generate_table_id(prefix: &str) -> String {
        let mut k = init_key_manager(
            None, 
            Some("asdfghjklqwertyuiopzxcvbnmASDFGHJKLQWERTYUIOPZXCVBNM1234567890_-"));
        let mut table_id = k.generate_keyless_id::<TableName>(&prefix, b"table name", None, None).unwrap();
        table_id.encoded_id.insert(prefix.len(), '-');
        table_id.encoded_id
    }

    /// Run with cargo test -- --nocapture
    #[test]
    fn generate_table_ids() {
        let stores_table_name = generate_table_id("STORES");
        println!("Stores table name: {}", stores_table_name);
        
        let products_table_name = generate_table_id("PRODUCTS");
        println!("Products table name: {}", products_table_name);

        let licenses_table_name = generate_table_id("LICENSES");
        println!("Licenses table name: {}", licenses_table_name);

        let machines_table_name = generate_table_id("MACHINES");
        println!("Machines table name: {}", machines_table_name);
    }
}