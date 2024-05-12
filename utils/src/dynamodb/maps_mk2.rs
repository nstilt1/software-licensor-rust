//! My second attempt at simplifying the `HashMap<String, AttributeValue>` 
//! with some boilerplate code.

use std::collections::HashMap;
//pub use proto::prost::bytes::Bytes;
pub use bytes::Bytes;
use rusoto_dynamodb::AttributeValue;

use crate::error::ApiError;

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
/// let mut map = AttributeValueHashMap::new();
///       
/// map.insert_attr_val::<S>("some string's key", "Test 1".into());
/// assert_eq!(map.get_attr_val::<S>("some string's key").unwrap(), "Test 1");
///
/// map.insert_attr_val::<N>("some number's key", "5".into());
/// assert_eq!(map.get_attr_val::<N>("some number's key").unwrap(), "5");
///
/// map.insert_attr_val::<B>("some binary data's key", b"testing slice".as_slice().into());
/// let expected: Bytes = b"testing slice".as_slice().into();
/// assert_eq!(map.get_attr_val::<B>("some binary data's key").unwrap(), &expected);
/// ```

pub type AttributeValueHashMap = HashMap<String, AttributeValue>;
pub trait AbstractAttributeValueMaps {
    fn insert_attr_val<A: AttrValAbstraction>(&mut self, key: &str, data: A::ArgType);
    fn get_attr_val<A: AttrValAbstraction>(&self, key: &str) -> Result<&A::ArgType, ApiError>;
}

impl AbstractAttributeValueMaps for AttributeValueHashMap {
    #[inline]
    fn insert_attr_val<A: AttrValAbstraction>(&mut self, key: &str, data: A::ArgType) {
        self.insert(key.to_string(), A::attribute_value(data));
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
}

pub trait AttrValAbstraction {
    /// The argument type for initializing an `AttributeValue`
    type ArgType;
    /// Initializes an `AttributeValue` from an `ArgType`
    fn attribute_value(data: Self::ArgType) -> AttributeValue;
    /// Gets the `ArgType` from an `AttributeValue`
    fn get_val(attr_val: &AttributeValue) -> Option<&Self::ArgType>;
}

macro_rules! impl_attr_val_abstraction {
    ($struct:ident, $arg_type:ty, $member_name:ident, $doc:expr) => {
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
        }
    };
}
impl_attr_val_abstraction!(B, Bytes, b, "The `Binary` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(Bool, bool, bool, "The `Boolean` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(BS, Vec<Bytes>, bs, "The `Binary Set` generic type for an `AttributeValue`");
// `List` is not implemented because it seems like a great way to cause errors
impl_attr_val_abstraction!(M, AttributeValueHashMap, m, "The `Map` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(N, String, n, "The `Number` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(NS, Vec<String>, ns, "The `Number Set` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(S, String, s, "The `String` generic type for an `AttributeValue`");
impl_attr_val_abstraction!(SS, Vec<String>, ss, "The `String Set` generic type for an `AttributeValue`");

/*
pub struct B;
impl AttrValAbstraction for B {
    type ArgType = BytesWrapper;
    #[inline]
    fn attribute_value(data: Self::ArgType) -> AttributeValue {
        AttributeValue {
            b: Some(data.0),
            ..Default::default()
        }
    }
    #[inline]
    fn get_val(attr_val: &AttributeValue) -> Option<&Self::ArgType> {
        attr_val.b.as_ref()
    }
}
*/

#[cfg(test)]
mod tests {
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
    }
}