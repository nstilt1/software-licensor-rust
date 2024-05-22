use http_private_key_manager::ProtocolError;
use lambda_http::{Response, Body, Error};

pub mod into;

#[derive(Debug)]
pub enum ApiError {
    InvalidAuthentication,
    ProtocolError(ProtocolError),
    RequestWentThrough,
    IdExpired,
    DynamoDbResourceNotFound(String),
    DynamoDbError(String),
    InvalidRequest(String),
    InvalidDbSchema(String),
    ServerError(String),
    NotFound,
    ThroughputError,
    // licensing errors:
    IncorrectOfflineCode,
    LicenseNoLongerActive,
    NoLicenseFound,
    OverMaxMachines,
    TrialEnded,
    InvalidLicenseCode,
    OfflineIsNotAllowed
}

impl ApiError {
    fn get_status_code(&self) -> u16 {
        match self {
            Self::IdExpired => 403,
            Self::InvalidAuthentication => 401,
            Self::ProtocolError(_) => 403,
            Self::RequestWentThrough => 202,
            Self::DynamoDbError(_) => 500,
            Self::DynamoDbResourceNotFound(_) => 404,
            Self::InvalidRequest(_) => 400,
            Self::InvalidDbSchema(_) => 500,
            Self::ServerError(_) => 500,
            Self::NotFound => 404,
            Self::ThroughputError => 500,
            // licensing errors
            Self::IncorrectOfflineCode => 403,
            Self::LicenseNoLongerActive => 403,
            Self::NoLicenseFound => 403,
            Self::OverMaxMachines => 403,
            Self::TrialEnded => 403,
            Self::InvalidLicenseCode => 403,
            Self::OfflineIsNotAllowed => 403,
        }
    }
}

macro_rules! write_fmt {
    ($f:expr, $fmt:expr, $repl:expr) => {
        $f.write_fmt(format_args!($fmt, $repl))
    };
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(debug_assertions)]
        {
            match self {
                Self::IdExpired => f.write_str("The token has expired"),
                Self::InvalidAuthentication => f.write_str("The authentication was invalid"),
                Self::RequestWentThrough => f.write_str("There was an error, but your request went through"),
                Self::ProtocolError(x) => write_fmt!(f, "There was a protocol error, {}", x),
                Self::DynamoDbError(x) => write_fmt!(f, "There was an internal server error, {}", x),
                Self::DynamoDbResourceNotFound(x) => write_fmt!(f, "Resource not found: {}", x),
                Self::InvalidRequest(x) => write_fmt!(f, "Invalid request: {}", x),
                Self::InvalidDbSchema(x) => write_fmt!(f, "Invalid DB schema: {}", x),
                Self::ServerError(x) => write_fmt!(f, "Internal server error: {}", x),
                Self::NotFound => f.write_str("Not found; perhaps the resource was not in the database."),
                Self::ThroughputError => f.write_str("There was a throughput error. Try again in a few minutes"),
                // licensing errors
                Self::IncorrectOfflineCode => f.write_str("32"),
                Self::LicenseNoLongerActive => f.write_str("16"),
                Self::NoLicenseFound => f.write_str("2"),
                Self::OverMaxMachines => f.write_str("4"),
                Self::TrialEnded => f.write_str("8"),
                Self::InvalidLicenseCode => f.write_str("2"),
                Self::OfflineIsNotAllowed => f.write_str("64"),
            }
        }
        #[cfg(not(debug_assertions))]
        {f.write_str(
            match self.error_type {
                Self::IdExpired => format_args!("The token has expired"),
                Self::RequestWentThrough => format_args!("There was an error, but your request went through"),
                Self::DynamoDbError(x) => format_args!("There was an internal server error"),
                Self::ServerError(x) => write_fmt!(f, "There was an internal server error: {}", x),
                Self::InvalidRequest(x) => write_fmt!(f, "Invalid request: {}", x),
                Self::NotFound => "Not Found",
                Self::ThroughputError => "The servers are a bit busy at the momement. Try again in a few minutes",
                // licensing errors
                Self::IncorrectOfflineCode => f.write_str("32"),
                Self::LicenseNoLongerActive => f.write_str("16"),
                Self::NoLicenseFound => f.write_str("2"),
                Self::OverMaxMachines => f.write_str("4"),
                Self::TrialEnded => f.write_str("8"),
                Self::InvalidLicenseCode => f.write_str("2"),
                Self::OfflineIsNotAllowed => f.write_str("64"),
                _ => format_args!("Forbidden")
            }
        )}
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    /// Turns an error into a 202 error
    pub fn _202(&mut self) {
        *self = Self::RequestWentThrough
    }

    /// Returns an error response.
    /// 
    /// TODO: consider encrypting the error message along with a timestamp and 
    /// other metadata; maybe generate a request ID
    pub fn respond(&self) -> Result<lambda_http::Response<Body>, Error> {
        return Self::error_resp(self.get_status_code(), &self.to_string());
    }

    /// Creates an error response
    fn error_resp(code: u16, message: &str) -> Result<Response<Body>, Error> {
        return Ok(Response::builder()
            .status(code)
            .header("content-type", "text/html")
            .body(message.into())
            .map_err(Box::new)?);
    }
}