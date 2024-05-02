use std::num::{ParseFloatError, ParseIntError};

use super::ApiError;
use base64::DecodeError;
use http_private_key_manager::ProtocolError;
use http_private_key_manager::private_key_generator::error::InvalidId;
use rusoto_core::RusotoError;
use rusoto_dynamodb::BatchGetItemError;

impl From<ProtocolError> for ApiError {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::InvalidId(InvalidId::Expired) => Self::IdExpired,
            _ => Self::ProtocolError(err),
        }
    }
}

impl From<RusotoError<BatchGetItemError>> for ApiError {
    fn from(value: RusotoError<BatchGetItemError>) -> Self {
        match value {
            RusotoError::Service(BatchGetItemError::ResourceNotFound(x)) => Self::DynamoDbResourceNotFound(x),
            _ => Self::DynamoDbError(value.to_string())
        }
    }
}

impl From<ParseFloatError> for ApiError {
    fn from(value: ParseFloatError) -> Self {
        Self::ServerError(format!("Parse float error: {}", value))
    }
}

impl From<ParseIntError> for ApiError {
    fn from(value: ParseIntError) -> Self {
        Self::ServerError(format!("Parse int error: {}", value))
    }
}

impl From<DecodeError> for ApiError {
    fn from(value: DecodeError) -> Self {
        Self::ServerError(format!("base64 DecodeError: {}", value))
    }
}