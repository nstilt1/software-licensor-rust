use std::num::{ParseFloatError, ParseIntError};

use super::ApiError;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::error::BuildError;
use base64::DecodeError;
use http_private_key_manager::ProtocolError;
use http_private_key_manager::private_key_generator::error::{IdCreationError, InvalidId};
use aws_sdk_dynamodb::operation::{
    get_item::GetItemError,
    batch_get_item::BatchGetItemError,
    batch_write_item::BatchWriteItemError,
    put_item::PutItemError,
};
impl From<ProtocolError> for ApiError {
    fn from(err: ProtocolError) -> Self {
        match err {
            ProtocolError::InvalidId(InvalidId::Expired) => Self::IdExpired,
            ProtocolError::SigningError => Self::ServerError("Signing key error".into()),
            _ => Self::ProtocolError(err),
        }
    }
}

impl From<BatchGetItemError> for ApiError {
    fn from(value: BatchGetItemError) -> Self {
        match value {
            BatchGetItemError::InternalServerError(x) => Self::ServerError(x.to_string()),
            BatchGetItemError::InvalidEndpointException(x) => Self::ServerError(x.to_string()),
            BatchGetItemError::ProvisionedThroughputExceededException(_) => Self::ThroughputError,
            BatchGetItemError::RequestLimitExceeded(_) => Self::ThroughputError,
            BatchGetItemError::ResourceNotFoundException(_) => Self::NotFound,
            _ => Self::ServerError(value.to_string()),
        }
    }
}

impl From<SdkError<BatchGetItemError>> for ApiError {
    fn from(value: SdkError<BatchGetItemError>) -> Self {
        value.into()
    }
}

impl From<BuildError> for ApiError {
    fn from(value: BuildError) -> Self {
        Self::ServerError(value.to_string())
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
            GetItemError::InternalServerError(e) => Self::ServerError(e.to_string()),
            GetItemError::ProvisionedThroughputExceededException(_e) => Self::ThroughputError,
            GetItemError::RequestLimitExceeded(_e) => Self::ThroughputError,
            GetItemError::InvalidEndpointException(e) => Self::ServerError(e.to_string()),
            GetItemError::ResourceNotFoundException(_) => Self::NotFound,
            _ => todo!(),
        }
    }
}

impl From<SdkError<GetItemError>> for ApiError {
    fn from(value: SdkError<GetItemError>) -> Self {
        value.into()
    }
}

impl From<PutItemError> for ApiError {
    fn from(value: PutItemError) -> Self {
        ApiError::DynamoDbError(value.to_string())
    }
}

impl From<SdkError<PutItemError>> for ApiError {
    fn from(value: SdkError<PutItemError>) -> Self {
        value.into()
    }
}

impl From<BatchWriteItemError> for ApiError {
    fn from(value: BatchWriteItemError) -> Self {
        match value {
            BatchWriteItemError::InternalServerError(e) => Self::ServerError(e.to_string()),
            BatchWriteItemError::RequestLimitExceeded(_e) => Self::ThroughputError,
            BatchWriteItemError::ItemCollectionSizeLimitExceededException(_) => Self::ThroughputError,
            BatchWriteItemError::ProvisionedThroughputExceededException(_) => Self::ThroughputError,
            BatchWriteItemError::ResourceNotFoundException(_) => Self::NotFound,
            _ => Self::ServerError(value.to_string()),
        }
    }
}

impl From<SdkError<BatchWriteItemError>> for ApiError {
    fn from(value: SdkError<BatchWriteItemError>) -> Self {
        value.into()
    }
}