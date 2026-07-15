#![forbid(unsafe_code)]

mod connector;

pub use connector::{MariaDbConnector, MySqlConnector};
