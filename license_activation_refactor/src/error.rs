use utils::{error::ApiError, prelude::proto::protos::create_product_request::LanguageSupport};

#[derive(Debug)]
pub enum LicensingError {
    InvalidStoreId,
    InvalidProductId,
    InvalidLicenseCode,
    InvalidOfflineCode(LanguageSupport),
    OverMachineLimit(LanguageSupport),
    LicenseNoLongerActive(LanguageSupport),
    TrialEnded(LanguageSupport),
    ApiError(ApiError),
}

impl std::fmt::Display for LicensingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidLicenseCode => "400a",
            Self::InvalidOfflineCode(l) => &l.incorrect_offline_code,
            Self::InvalidProductId => "400b",
            Self::InvalidStoreId => "400c",
            Self::LicenseNoLongerActive(l) => &l.license_no_longer_active,
            Self::OverMachineLimit(l) => &l.over_max_machines,
            Self::TrialEnded(l) => &l.trial_ended,
            Self::ApiError(a) => &a.to_string()
        })
    }
}

impl From<ApiError> for LicensingError {
    fn from(value: ApiError) -> Self {
        Self::ApiError(value)
    }
}

impl std::error::Error for LicensingError {}