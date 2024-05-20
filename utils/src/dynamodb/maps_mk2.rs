//! My second attempt at simplifying the `HashMap<String, AttributeValue>` 
//! with some boilerplate code.

use std::collections::HashMap;
//pub use proto::prost::bytes::Bytes;
pub use bytes::Bytes;
use rusoto_dynamodb::AttributeValue;

use crate::error::ApiError;
use crate::tables::Item;

/// Abstracts the creation and retrieval of `AttributeValue`s from a HashMap.
/// 
/// The available generics that can be used are:
/// 
/// * `B` - binary data (Bytes)
/// * `Bool` - Booleans
/// * `BS` - binary sets (Vec<Bytes>)
/// * `M` - Map (HashMap<String, AttributeValue>) or AttributeValueHashMap
/// * `N` - Number (String)
/// * `NS` - Number Set (Vec<String>)
/// * `S` - String
/// * `SS` - String Set (Vec<String>)
/// 
/// Note: `List` is not implemented due to the fact that it might cause a lot of
/// trouble for developers. The elements of a list are not identifiable by a 
/// key and can have any type, opening the door for runtime errors. Consider 
/// using a map or set instead; that way, you will know what type each item is 
/// supposed to be, and maps allow you to associate a name with each value.
/// 
/// Also, this crate packages some data within Protocol Buffers. This allows for 
/// the data to be compacted and makes the data a little easier to access from 
/// code. It also allows you to encrypt the entire message. The downside is that
/// the contents aren't indexable with a secondary index and they cannot be 
/// easily analyzed with services such as AWS Athena. This means its primary 
/// use in a database might be for private data, unless you don't plan on using 
/// something like AWS Athena and want to have smaller database items.
/// 
/// # Example
/// ```rust
/// use utils::dynamodb::maps_mk2::*;
/// use utils::tables::Item;
/// let mut map = AttributeValueHashMap::new();
/// 
/// pub struct ExampleDbTable {
///     pub table_name: &'static str,
///     pub number_item_example: Item<N>,
///     pub string_item_example: Item<S>,
///     pub binary_item_example: Item<B>,
/// };
/// 
/// const EXAMPLE_TABLE: ExampleDbTable = ExampleDbTable {
///     table_name: "EXAMPLE-table-name",
///     number_item_example: Item::new("number_item_key"),
///     string_item_example: Item::new("string_item_key"),
///     binary_item_example: Item::new("Binary_item_key"),
/// };
/// 
/// map.insert_item(EXAMPLE_TABLE.number_item_example, 5.to_string());
/// assert_eq!(map.get_item(EXAMPLE_TABLE.number_item_example).unwrap(), &5.to_string());
///
/// map.insert_item_into(EXAMPLE_TABLE.string_item_example, "test");
/// assert_eq!(map.get_item(EXAMPLE_TABLE.string_item_example).unwrap(), "test");
///
/// map.insert_item_into(EXAMPLE_TABLE.binary_item_example, b"testing slice".to_vec());
/// let expected: Bytes = b"testing slice".as_slice().into();
/// assert_eq!(map.get_item(EXAMPLE_TABLE.binary_item_example).unwrap(), &expected);
/// ```

pub type AttributeValueHashMap = HashMap<String, AttributeValue>;
trait AbstractAttributeValueMaps {
    /// Inserts an attribute value into an AttributeValueHashMap
    fn insert_attr_val<A: AttrValAbstraction>(&mut self, key: &str, data: A::ArgType);
    /// Inserts an attribute value into an AttributeValueHashMap, but calls .into() on the input data.
    fn insert_attr_val_into<A: AttrValAbstraction, B: Into<A::ArgType>>(&mut self, key: &str, data: B);
    /// Gets an attribute value.
    fn get_attr_val<A: AttrValAbstraction>(&self, key: &str) -> Result<&A::ArgType, ApiError>;
    /// Gets a mutable attribute value
    fn get_attr_val_mut<A: AttrValAbstraction>(&mut self, key: &str) -> Result<&mut A::ArgType, ApiError>;
}

impl AbstractAttributeValueMaps for AttributeValueHashMap {
    #[inline]
    fn insert_attr_val<A: AttrValAbstraction>(&mut self, key: &str, data: A::ArgType) {
        self.insert(key.to_string(), A::attribute_value(data));
    }
    #[inline]
    fn insert_attr_val_into<A: AttrValAbstraction, B: Into<A::ArgType>>(&mut self, key: &str, data: B) {
        self.insert(key.to_string(), A::attribute_value(data.into()));
    }
    #[inline]
    fn get_attr_val<A: AttrValAbstraction>(&self, key: &str) -> Result<&A::ArgType, ApiError> {
        let attr_val = match self.get(key) {
            Some(x) => x,
            None => return Err(ApiError::InvalidDbSchema("Key `{}` was not in the hashmap".into()))
        };
        let val = match A::get_val(attr_val) {
            Some(v) => v,
            None => return Err(ApiError::InvalidDbSchema(format!("Key `{}` AttributeValue had a mismatched type in the database", key)))
        };
        Ok(val)
    }
    #[inline]
    fn get_attr_val_mut<A: AttrValAbstraction>(&mut self, key: &str) -> Result<&mut A::ArgType, ApiError> {
        let attr_val = match self.get_mut(key) {
            Some(x) => x,
            None => return Err(ApiError::InvalidDbSchema("Key `{}` was not in the hashmap".into()))
        };
        let val = match A::get_val_mut(attr_val) {
            Some(v) => v,
            None => return Err(ApiError::InvalidDbSchema(format!("Key `{}` AttributeValue had a mismatched type in the database", key)))
        };
        Ok(val)
    }
}

pub trait AttrValAbstraction {
    /// The argument type for initializing an `AttributeValue`.
    type ArgType;
    /// Gets the string value of an `ArgType`.
    fn get_str_val(v: &Self::ArgType) -> String;
    /// Initializes an `AttributeValue` from an `ArgType`.
    fn attribute_value(data: Self::ArgType) -> AttributeValue;
    /// Gets the `ArgType` from an `AttributeValue`.
    fn get_val(attr_val: &AttributeValue) -> Option<&Self::ArgType>;
    /// Gets a mutable `ArgType` from an `AttributeValue`.
    fn get_val_mut(attr_val: &mut AttributeValue) -> Option<&mut Self::ArgType>;
}

macro_rules! write_get_str_val {
    (true) => {
        #[inline]
        fn get_str_val(v: &Self::ArgType) -> String {
            v.to_string()
        }
    };
    (false) => {
        #[inline]
        fn get_str_val(_v: &Self::ArgType) -> String {
            "Error: Cannot display data".into()
        }
    }
}

macro_rules! impl_attr_val_abstraction {
    ($struct:ident, $arg_type:ty, $member_name:ident, $use_to_string:tt, $doc:expr) => {
        #[doc = $doc]
        pub struct $struct;
        impl AttrValAbstraction for $struct {
            type ArgType = $arg_type;
            #[inline]
            fn attribute_value(data: Self::ArgType) -> AttributeValue {
                AttributeValue {
                    $member_name: Some(data),
                    ..Default::default()
                }
            }
            #[inline]
            fn get_val(attr_val: &AttributeValue) -> Option<&Self::ArgType> {
                attr_val.$member_name.as_ref()
            }
            #[inline]
            fn get_val_mut(attr_val: &mut AttributeValue) -> Option<&mut Self::ArgType> {
                attr_val.$member_name.as_mut()
            }
            write_get_str_val!($use_to_string);
        }
    };
}

impl_attr_val_abstraction!(B, Bytes, b, false, "The `Binary` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(Bool, bool, bool, true, "The `Boolean` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(BS, Vec<Bytes>, bs, false, "The `Binary Set` generic type for an `AttributeValue`");
// `List` is not implemented because it seems like a great way to cause errors
impl_attr_val_abstraction!(M, AttributeValueHashMap, m, false, "The `Map` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(N, String, n, true, "The `Number` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(NS, Vec<String>, ns, false, "The `Number Set` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(S, String, s, true, "The `String` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(SS, Vec<String>, ss, false, "The `String Set` generic type for an `AttributeValue`");

pub trait ItemIntegration {
    /// Inserts an item into the `AttributeValueHashMap`.
    fn insert_item<T: AttrValAbstraction>(&mut self, item: Item<T>, value: T::ArgType);
    /// Inserts an item into the `AttributeValueHashMap`, calling `.into()` on the value.
    fn insert_item_into<T: AttrValAbstraction, I: Into<T::ArgType>>(&mut self, item: Item<T>, value: I);
    /// Gets the value for an item from an `AttributeValueHashMap`.
    fn get_item<T: AttrValAbstraction>(&self, item: Item<T>) -> Result<&T::ArgType, ApiError>;
    /// Gets a mutable reference to an item value from an `AttributeValueHashMap`.
    fn get_item_mut<T: AttrValAbstraction>(&mut self, item: Item<T>) -> Result<&mut T::ArgType, ApiError>;
    /// Gets a reference to a hashmap. Useful for dynamically named hashmaps.
    fn get_map_by_str(&self, key: &str) -> Result<&<M as AttrValAbstraction>::ArgType, ApiError>;
    /// Gets a mutable reference to a hashmap. Useful for dynamically named hashmaps.
    fn get_mut_map_by_str(&mut self, key: &str) -> Result<&mut <M as AttrValAbstraction>::ArgType, ApiError>;
}

impl ItemIntegration for AttributeValueHashMap {
    #[inline]
    fn insert_item<T: AttrValAbstraction>(&mut self, item: Item<T>, value: T::ArgType) {
        self.insert_attr_val::<T>(item.key, value)
    }
    #[inline]
    fn insert_item_into<T: AttrValAbstraction, I: Into<T::ArgType>>(&mut self, item: Item<T>, value: I) {
        self.insert_attr_val_into::<T, I>(item.key, value)
    }
    #[inline]
    fn get_item<T: AttrValAbstraction>(&self, item: Item<T>) -> Result<&T::ArgType, ApiError> {
        self.get_attr_val::<T>(item.key)
    }
    #[inline]
    fn get_item_mut<T: AttrValAbstraction>(&mut self, item: Item<T>) -> Result<&mut T::ArgType, ApiError> {
        self.get_attr_val_mut::<T>(item.key)
    }
    #[inline]
    fn get_map_by_str(&self, key: &str) -> Result<&<M as AttrValAbstraction>::ArgType, ApiError> {
        self.get_attr_val::<M>(key)
    }
    #[inline]
    fn get_mut_map_by_str(&mut self, key: &str) -> Result<&mut <M as AttrValAbstraction>::ArgType, ApiError> {
        self.get_attr_val_mut::<M>(key)
    }
}

/// Allows the insertion and retrieval of null values into an AttributeValueHashMap
pub trait NullableFields {
    /// Inserts a null value in place of an Item's value.
    fn insert_null<T: AttrValAbstraction>(&mut self, key: Item<T>);
    /// Gets a potentially null value.
    /// 
    /// These valid types return a string representing the value:
    /// * S (String)
    /// * N (Number)
    /// * Bool (Boolean)
    /// 
    /// These invalid types return "Error: Cannot display data":
    /// * B (Binary)
    /// * BS (Binary Set)
    /// * M (Map)
    /// * NS (Number Set)
    /// * SS (String Set)
    fn get_potential_null<T: AttrValAbstraction>(&self, key: Item<T>) -> Result<String, ApiError>;
}

impl NullableFields for AttributeValueHashMap {
    #[inline]
    fn insert_null<T: AttrValAbstraction>(&mut self, key: Item<T>) {
        self.insert(key.key.into(), AttributeValue { null: Some(true), ..Default::default() } );
    }
    #[inline]
    fn get_potential_null<T: AttrValAbstraction>(&self, key: Item<T>) -> Result<String, ApiError> {
        let attr_val = match self.get(key.key) {
            Some(x) => x,
            None => return Err(ApiError::InvalidDbSchema(format!("Key `{}` was not in the hashmap", key.key)))
        };
        match attr_val.null {
            Some(_x) => Ok("Not provided.".into()),
            None => {
                match T::get_val(attr_val) {
                    Some(v) => Ok(T::get_str_val(v)),
                    None => Err(ApiError::InvalidDbSchema(format!("Key `{}` had a type issue", key.key)))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tables::stores::STORES_TABLE;

    use super::*;

    #[test]
    fn generics() {
        let mut map: HashMap<String, AttributeValue> = HashMap::new();
        
        let (key, expected) = ("test_bytes", b"expected");
        map.insert_attr_val::<B>(key, expected.as_slice().into());
        assert_eq!(map.get_attr_val::<B>(key).unwrap().to_vec(), expected);

        let (key, expected) = ("test_bool", true);
        map.insert_attr_val::<Bool>(key, expected);
        assert_eq!(map.get_attr_val::<Bool>(key).unwrap(), &expected);

        let (key, expected) = ("test_1", "Test 1");
        map.insert_attr_val::<S>(key, expected.to_string());
        assert_eq!(map.get_attr_val::<S>(key).unwrap(), expected);

        map.insert_attr_val::<N>("test_2", "5".into());
        assert_eq!(map.get_attr_val::<N>("test_2").unwrap(), "5");

        map.insert_item_into(STORES_TABLE.num_auths, "4");
    }
}

