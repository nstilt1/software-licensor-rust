use http_private_key_manager::ProtocolError;
use lambda_http::{http::StatusCode, Body, Error, Response};

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
    StoreAlreadyRegistered,
    // licensing errors:
    IncorrectOfflineCode,
    LicenseNoLongerActive,
    NoLicenseFound,
    OverMaxMachines,
    TrialEnded,
    InvalidLicenseCode,
    OfflineIsNotAllowed,
    MachineDeactivated,
}

impl ApiError {
    #[inline]
    fn get_status_code(&self) -> StatusCode {
        let status = match self {
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
            Self::StoreAlreadyRegistered => 401,
            // licensing errors
            Self::IncorrectOfflineCode => 403,
            Self::LicenseNoLongerActive => 403,
            Self::NoLicenseFound => 403,
            Self::OverMaxMachines => 403,
            Self::TrialEnded => 403,
            Self::InvalidLicenseCode => 403,
            Self::OfflineIsNotAllowed => 403,
            Self::MachineDeactivated => 403,
        };
        StatusCode::from_u16(status).expect("Invalid status code")
    }

    #[inline]
    pub fn get_licensing_error_number(&self) -> u32 {
        match self {
            Self::IncorrectOfflineCode => 32,
            Self::LicenseNoLongerActive => 16,
            Self::NoLicenseFound => 2,
            Self::OverMaxMachines => 4,
            Self::TrialEnded => 8,
            Self::InvalidLicenseCode => 128,
            Self::OfflineIsNotAllowed => 64,
            Self::MachineDeactivated => 256,
            _ => 512
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
        #[cfg(feature = "debug")]
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
                Self::StoreAlreadyRegistered => f.write_str("The store's public key's length is not equal to 0 in the database."),
                // licensing errors
                Self::IncorrectOfflineCode => f.write_str("32"),
                Self::LicenseNoLongerActive => f.write_str("16"),
                Self::NoLicenseFound => f.write_str("2"),
                Self::OverMaxMachines => f.write_str("4"),
                Self::TrialEnded => f.write_str("8"),
                Self::InvalidLicenseCode => f.write_str("128"),
                Self::OfflineIsNotAllowed => f.write_str("64"),
                Self::MachineDeactivated => f.write_str("256"),
            }
        }
        #[cfg(not(feature = "debug"))]
        {
            match self {
                Self::IdExpired => f.write_str("The token has expired"),
                Self::RequestWentThrough => f.write_str("There was an error, but your request went through"),
                Self::DynamoDbError(_) => f.write_str("There was an internal server error"),
                Self::DynamoDbResourceNotFound(e) => f.write_str(e),
                Self::InvalidDbSchema(e) => f.write_str(e),
                Self::ProtocolError(e) => f.write_str(&e.to_string()),
                Self::InvalidAuthentication => f.write_str("Forbidden"),
                Self::ServerError(x) => write_fmt!(f, "There was an internal server error: {}", x),
                Self::InvalidRequest(x) => write_fmt!(f, "Invalid request: {}", x),
                Self::NotFound => f.write_str("Not Found"),
                Self::ThroughputError => f.write_str("The servers are a bit busy at the momement. Try again in a few minutes"),
                Self::StoreAlreadyRegistered => f.write_str("This API key is already in use"),
                // licensing errors
                Self::IncorrectOfflineCode => f.write_str("32"),
                Self::LicenseNoLongerActive => f.write_str("16"),
                Self::NoLicenseFound => f.write_str("2"),
                Self::OverMaxMachines => f.write_str("4"),
                Self::TrialEnded => f.write_str("8"),
                Self::InvalidLicenseCode => f.write_str("128"),
                Self::OfflineIsNotAllowed => f.write_str("64"),
                Self::MachineDeactivated => f.write_str("256"),
            }
        }
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
        Ok(Response::builder()
            .status(self.get_status_code())
            .header("content-type", "text/html")
            .body(self.to_string().into())
            .expect("Unable to build http::Response")) 
    }
}