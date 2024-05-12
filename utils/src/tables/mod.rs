//! Module containing database table information, including:
//! * table names
//! * table layout
//! * item names

pub mod stores;

pub struct Table<const N: usize> {
    pub name: &'static str,
    pub items: [Item; N]
}

pub struct Item {
    pub key: &'static str,
    pub ty: &'static str
}

impl AsRef<str> for Item {
    fn as_ref(&self) -> &str {
        self.key
    }
}

#[cfg(test)]
mod generating_ids {
    use super::super::crypto::*;
    use http_private_key_manager::prelude::*;
    type TableName = BinaryId<U48, U8, 16, use_timestamps::Never>;

    #[test]
    fn generate_table_ids() {
        let mut k = init_key_manager(
            None, 
            Some("asdfghjklqwertyuiopzxcvbnmASDFGHJKLQWERTYUIOPZXCVBNM1234567890_-"));
        let prefix = "STORES";
        let mut stores_table = k.generate_keyless_id::<TableName>(&prefix, b"table name", None, None).unwrap();
        stores_table.encoded_id.insert(prefix.len(), '-');
        println!("Stores table name: {}", stores_table.encoded_id);
    }
}