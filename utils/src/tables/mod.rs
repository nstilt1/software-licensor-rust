//! Module containing database table information, including:
//! * table names
//! * table layout
//! * item names

use std::marker::PhantomData;

use crate::prelude::AttrValAbstraction;

pub mod stores;
pub mod products;

pub struct Item<T: AttrValAbstraction> {
    pub key: &'static str,
    pub ty: PhantomData<T>
}

impl<T: AttrValAbstraction> Item<T> {
    pub const fn new(key: &'static str) -> Self {
        Self { key, ty: PhantomData}
    }
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
    }
}