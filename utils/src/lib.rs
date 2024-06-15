#![feature(lazy_cell)]

pub mod base64;
pub mod crypto;
#[cfg(feature = "dynamodb")]
pub mod dynamodb;
pub mod error;
#[cfg(feature = "dynamodb")]
pub mod tables;

pub mod function_handler_macro;

use std::time::{SystemTime, UNIX_EPOCH};

use error::ApiError;
use lambda_http::{Response, Body, Error as LambdaError};
use substring::Substring;
pub use http_private_key_manager::utils::StringSanitization;
pub use aws_config;

#[cfg(feature = "dynamodb")]
pub use aws_sdk_dynamodb;

#[cfg(feature = "s3")]
pub use aws_sdk_s3;
pub use lambda_runtime;
pub use serde_json;
#[cfg(feature = "lambda")]
pub use aws_sdk_lambda;
pub use http_private_key_manager::{debug_log, error_log};

/// The primary dependencies that will be required for lambda functions are re-exported so as to minimize the chance of different API methods having different versions of dependencies, which would result in more crates to download and compile.
pub mod prelude {
    pub use jemallocator;
    pub use http_private_key_manager;
    pub use lambda_http;
    pub use crate::crypto::*;
    pub use crate::error::*;
    pub use http_private_key_manager::{debug_log, error_log, Id, impl_handle_crypto};
    pub use proto::prost::Message;
    pub use crate::base64::Base64Vec;
    pub use tokio;
    pub use proto;
    #[cfg(feature = "dynamodb")]
    pub use crate::dynamodb::maps_mk2::*;
    #[cfg(feature = "dynamodb")]
    pub use aws_sdk_dynamodb::primitives::Blob;
    pub use tracing_subscriber;
    pub use tracing;
    pub use log;
    pub use crate::impl_function_handler;
}

pub trait OptionHandler<T> {
    /// Unwraps an Option that should be included in a request.
    /// 
    /// Returns an error if it isn't there.
    fn should_exist_in_request(&self) -> Result<&T, ApiError>;
    /// Unwraps an Option that should be in the database. This needs to be called 
    /// after the item is confirmed as present in the database.
    fn should_exist_in_db_schema(&self, key: &str) -> Result<&T, ApiError>;
    /// Unwraps an Option of a request that should be in the database
    fn should_exist_from_request(&self) -> Result<&T, ApiError> {
        self.should_exist_in_request()
    } 
}

impl<T> OptionHandler<T> for Option<T> {
    #[inline]
    fn should_exist_in_request(&self) -> Result<&T, ApiError> {
        if let Some(x) = self {
            return Ok(x)
        } else {
            return Err(ApiError::InvalidRequest("Item not found in request".into()))
        }
    }
    #[inline]
    fn should_exist_in_db_schema(&self, key: &str) -> Result<&T, ApiError> {
        if let Some(x) = self {
            return Ok(x)
        } else {
            return Err(ApiError::InvalidDbSchema(key.into()))
        }
    }
}

/// Remove any sabotage from the email address.
pub fn clean_email(input: &str) -> String {
    if input.contains("@gmail.com"){
        let at_sign = input.find('@').unwrap();
        let mut output = input.substring(0, at_sign).to_owned();
        output = output.replace(".", "");
        if output.contains('+') {
            output = output.substring(0, output.find('+').unwrap()).to_owned();
        }
        output.push_str(input.substring(at_sign, input.len()));
        return output;
    }
    return input.to_owned();
}

pub trait Comparing {
    /// Determines if a string is in a list of strings
    /// 
    /// TODO: evaluate where this function is called from and determine if it is
    /// still necessary
    fn exists_in(self, vector: Vec<&str>) -> bool;
}
impl Comparing for &str {
    fn exists_in(self, vector: Vec<&str>) -> bool {
        return vector.contains(&self);
    }
}
impl Comparing for String {
    fn exists_in(self, vector: Vec<&str>) -> bool {
        return vector.contains(&self.as_str());
    }
}

/// Returns SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
pub fn now_as_seconds() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).expect("now_as_seconds failed").as_secs()
}

/// Returns a success response
/// 
/// TODO: Switch to binary data / Protocol Buffers
pub fn success_resp(message: &str) -> Result<Response<Body>, LambdaError> {
    return Ok(Response::builder()
        .status(200)
        .header("content-type", "text/html")
        .body(message.into())
        .map_err(Box::new)?);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_handler() {
        let x: Option<u32> = Some(55);
        let y: Option<u32> = None;

        let x_r = x.should_exist_in_request();
        assert_eq!(x_r.is_ok(), true);
        let y_r = y.should_exist_in_request();
        assert_eq!(y_r.is_err(), true);
    }
}