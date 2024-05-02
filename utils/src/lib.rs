pub mod base64;
pub mod dynamodb;
pub mod error;

use error::ApiError;
use lambda_http::{Response, Body, Error as LambdaError};
use substring::Substring;

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
            return Err(ApiError::InvalidRequest)
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

pub fn cleanse (text: &str, extra_chars: &str, to_upper: bool) -> String {
    let mut allowed_chars = "ASDFGHJKLQWERTYUIOPZXCVBNM1234567890".to_owned();
    allowed_chars.push_str(extra_chars);
    let mut output = "".to_owned();
    for ch in text.chars() {
        let upper = ch.to_ascii_uppercase();
        if allowed_chars.contains(upper){
            output.push(if to_upper {upper} else {ch});
        }
    }
    output.to_owned()
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