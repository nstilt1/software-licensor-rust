//! Some constants for the Metrics table. This table is separate
//! from the stores table because DynamoDB writes cost more per 
//! KB than DynamoDB reads, and if there is extra data in each
//! item in the table, then we'd be paying for more.

use super::{Item, PrimaryHashKey};
use crate::dynamodb::maps_mk2::*;

pub struct MetricsTable {
    pub table_name: &'static str,
    /// primary index
    pub store_id: PrimaryHashKey<B>,
    /// This statistic serves as the amount of times that the 
    /// create_product API method has been called.
    pub num_products: Item<N>,
    /// This statistic serves as the amount of times that the 
    /// create_license API method has been called, but it is not 
    /// necessarily the amount of licenses distributed. Use store
    /// analytics tools to determine how many licenses have been
    /// purchased.
    pub num_licenses: Item<N>,
    /// The total number of licensed machines.
    pub num_licensed_machines: Item<N>,
    /// The total number of offline license activations.
    pub num_offline_machines: Item<N>,
    /// The total number of license activations
    pub num_license_activations: Item<N>,
    /// The number of times that a user has regenerated their license
    /// code.
    pub num_license_regens: Item<N>,
    /// The number of times a user has deactivated machines from 
    /// their license.
    pub num_machine_deactivations: Item<N>,
}

/// The Metrics Table Schema.
/// 
/// The primary key is simply the store's ID as it is represented
/// in the STORES table.
pub const METRICS_TABLE: MetricsTable = MetricsTable {
    table_name: "METRICS-wsSatspn7XCnipKQtjSEJ4dFZCpViyd1I9Io4P5hj0RLJG1Q840F7xoB",
    store_id: PrimaryHashKey { item: Item::new("id") },
    num_products: Item::new("num_products"),
    num_licenses: Item::new("num_licenses"),
    num_licensed_machines: Item::new("num_licensed_machines"),
    num_offline_machines: Item::new("num_offline_machines"),
    num_license_activations: Item::new("num_license_activations"),
    num_license_regens: Item::new("num_license_regens"),
    num_machine_deactivations: Item::new("num_machine_deactivations")
};