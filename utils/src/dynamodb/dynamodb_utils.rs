use std::collections::HashMap;

use rusoto_core::RusotoError;
use rusoto_dynamodb::{AttributeValue, BatchGetItemOutput, BatchGetItemError};

use crate::{error::ApiError, OptionHandler};

pub trait BatchGetUtils {
    fn get_item_vec_map(self) -> Result<HashMap<String, Vec<HashMap<String, AttributeValue>>>, ApiError>;
}

impl BatchGetUtils for Result<BatchGetItemOutput, RusotoError<BatchGetItemError>> {
    #[inline]
    fn get_item_vec_map(self) -> Result<HashMap<String, Vec<HashMap<String, AttributeValue>>>, ApiError> {
        let tables_and_items_opt = self?.responses;
        let tables = tables_and_items_opt.should_exist_from_request();
        return tables.cloned();
    }
}