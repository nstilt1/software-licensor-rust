use std::num::{ParseFloatError, ParseIntError};

use super::ApiError;
use base64::DecodeError;
use http_private_key_manager::ProtocolError;
use http_private_key_manager::private_key_generator::error::{IdCreationError, InvalidId};
use rusoto_core::RusotoError;
use rusoto_dynamodb::{BatchGetItemError, GetItemError, PutItemError};

impl From<ProtocolError> for ApiError {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::InvalidId(InvalidId::Expired) => Self::IdExpired,
            ProtocolError::SigningError => Self::ServerError("Signing key error".into()),
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

impl From<IdCreationError> for ApiError {
    fn from(value: IdCreationError) -> Self {
        Self::ServerError(format!("Error creating an ID: {}", value))
    }
}

impl From<InvalidId> for ApiError {
    fn from(_value: InvalidId) -> Self {
        Self::InvalidAuthentication
    }
}

impl From<p384::ecdsa::signature::Error> for ApiError {
    fn from(_value: p384::ecdsa::signature::Error) -> Self {
        Self::InvalidAuthentication
    }
}

impl From<p384::elliptic_curve::Error> for ApiError {
    fn from(_value: p384::elliptic_curve::Error) -> Self {
        Self::InvalidAuthentication
    }
}

impl From<GetItemError> for ApiError {
    fn from(value: GetItemError) -> Self {
        match value {
            GetItemError::InternalServerError(e) => Self::ServerError(e),
            GetItemError::ProvisionedThroughputExceeded(_e) => Self::ServerError("The servers are a bit busy at the moment. Try again in a few minutes".into()),
            GetItemError::RequestLimitExceeded(_e) => return Self::ServerError("The servers are a bit busy at the momement. Try again in a few minutes".into()),
            GetItemError::ResourceNotFound(e) => return Self::ServerError(format!("Error: resource not found; {}", e))
        }
    }
}

impl From<RusotoError<GetItemError>> for ApiError {
    fn from(value: RusotoError<GetItemError>) -> Self {
        value.into()
    }
}

impl From<PutItemError> for ApiError {
    fn from(value: PutItemError) -> Self {
        ApiError::DynamoDbError(value.to_string())
    }
}

impl From<RusotoError<PutItemError>> for ApiError {
    fn from(value: RusotoError<PutItemError>) -> Self {
        value.into()
    }
}