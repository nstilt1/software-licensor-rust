//! Some constants for the Plugins/Products Table

use super::Item;
use crate::dynamodb::maps_mk2::*;

pub struct ProductsTable {
    pub table_name: &'static str,
    /// primary index
    pub id: Item<B>,
    /// this hashed store ID will be a secondary index
    pub hashed_store_id: Item<B>,
    pub num_machines_total: Item<N>,
    pub num_licenses_total: Item<N>,
    pub num_offline_machines: Item<N>,
    pub num_subscription_machines: Item<N>,
    pub num_perpetual_machines: Item<N>,
    pub num_license_auths: Item<N>,
    pub is_offline_allowed: Item<Bool>,
    pub max_machines_per_license: Item<N>,
    /// version
    /// store_id
    /// plugin name
    /// language support map - key = lang_name
    /// - IncorrectOfflineCode
    /// - LicenseNoLongerActive
    /// - NoLicenseFound
    /// - OverMaxMachines
    /// - Trial Ended
    /// - Success
    /// 
    /// isOfflineEnabled
    /// isOnlineEnabled
    /// maxMachinesPerLicense
    /// 
    /// offlineLicenseFrequencyHours
    /// 
    /// perpetualLicenseExpirationDays
    /// perpetualLicenseFrequencyHours
    /// 
    /// subscriptionLicenseExpirationDays
    /// subscriptionLicenseExpirationLeniencyHours
    /// subscriptionLicenseFrequencyHours
    /// 
    /// trialLicenseExpirationDays
    /// trialLicenseFrequencyHours
    pub protobuf_data: Item<B>,
}

pub const PRODUCTS_TABLE: ProductsTable = ProductsTable {
    table_name: "PRODUCTS-BMEvbp9AszCuk5pZg_yt6f_rinRsdIycprMMcNzMYkljl94EPpstEfjr",
    id: Item::new("hashed_id"),
    protobuf_data: Item::new("data"),
    hashed_store_id: Item::new("store_id_hash"),
    num_machines_total: Item::new("total_machines"),
    num_licenses_total: Item::new("total_licenses"),
    num_offline_machines: Item::new("num_off_machines"),
    num_subscription_machines: Item::new("num_s_machines"),
    num_perpetual_machines: Item::new("num_p_machines"),
    num_license_auths: Item::new("total_license_auths"),
    is_offline_allowed: Item::new("allow_offline"),
    max_machines_per_license: Item::new("max_machines_per_license"),
};

