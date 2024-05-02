use openssl::error::ErrorStack;

use super::HttpError;




impl From<ErrorStack> for HttpError {
    fn from(value: ErrorStack) -> Self {
        (500, value.to_string()).into()
    }
}