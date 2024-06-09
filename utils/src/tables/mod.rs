//! Module containing database table information, including:
//! * table names
//! * table layout
//! * item names

use std::marker::PhantomData;

#[cfg(feature = "dynamodb")]
use crate::prelude::{AttrValAbstraction, M};

#[cfg(feature = "dynamodb")]
pub mod stores;
#[cfg(feature = "dynamodb")]
pub mod products;
#[cfg(feature = "dynamodb")]
pub mod licenses;
#[cfg(feature = "dynamodb")]
pub mod machines;
#[cfg(feature = "dynamodb")]
pub mod metrics;

/// A trait that can abstract away the naming and types of DynamoDB
/// Attribute Values.
/// 
/// Attribute Values can be inserted or retrieved from
/// `AttributeValueHashMap`s via `insert_item` and `get_item`. While
/// these technically are not items, `item` rolls off the tongue a 
/// bit better than `attribute_value`.
pub trait DynamoDBAttributeValue {
    fn get_key(&self) -> &'static str;
    type ItemType: AttrValAbstraction;
}

pub struct Item<T: AttrValAbstraction> {
    pub key: &'static str,
    pub ty: PhantomData<T>
}

impl<T: AttrValAbstraction> DynamoDBAttributeValue for Item<T> {
    fn get_key(&self) -> &'static str {
        self.key
    }
    type ItemType = T;
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

impl<F> DynamoDBAttributeValue for MapItem<F> {
    fn get_key(&self) -> &'static str {
        self.key.key
    }
    type ItemType = M;
}

/// Implements DynamoDBAttributeValue for a struct whose only field is
/// `item` of type `Item<T>`.
macro_rules! impl_dynamodb_attr_val {
    ($struct:ident) => {
        impl<T: AttrValAbstraction> DynamoDBAttributeValue for $struct<T> {
            fn get_key(&self) -> &'static str {
                self.item.key
            }
            type ItemType = T;
        }
    };
}

/// A Primary Hash Key type of Attribute Value.
/// 
/// The purpose of this is for helping to distinguish which
/// `DynamoDBAttributeValue` in a struct is a Primary Hash Key.
pub struct PrimaryHashKey<T: AttrValAbstraction> {
    pub item: Item<T>
}

impl_dynamodb_attr_val!(PrimaryHashKey);

/// A Primary Sort Key type of Attribute Value.
/// 
/// The purpose of this is for helping to distinguish which
/// `DynamoDBAttributeValue` in a struct is a Primary Sort Key.
pub struct PrimarySortKey<T: AttrValAbstraction> {
    pub item: Item<T>
}

impl_dynamodb_attr_val!(PrimarySortKey);

/// A Global Secondary Index type of Attribute Value.
pub struct GlobalSecondaryIndex<T: AttrValAbstraction> {
    pub index_name: &'static str,
    pub item: Item<T>
}

impl<T: AttrValAbstraction> DynamoDBAttributeValue for GlobalSecondaryIndex<T> {
    fn get_key(&self) -> &'static str {
        self.item.key
    }
    type ItemType = T;
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