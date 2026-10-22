//! Shared node-data sync policy. A generation is trusted input, never another node's identity.
pub mod budget;
pub mod capture;
pub mod cas;
pub mod catalog;
pub mod collector;
pub mod context;
#[cfg(feature = "native")]
pub mod engine;
#[cfg(feature = "native")]
pub mod generation;
pub mod identity;
pub mod journal;
pub mod metadata;
pub mod model;
pub mod native_validation;
pub mod paths;
pub mod publisher;
pub mod records;
pub mod references;
pub mod safe_io;
pub mod service;
pub mod status;
pub mod trees;

#[cfg(feature = "native")]
pub mod operations;
#[cfg(feature = "native")]
pub mod worker;

#[cfg(test)]
extern crate self as node_data_sync;
#[cfg(test)]
#[path = "../tests/support/references.rs"]
mod test_references;

#[cfg(all(test, feature = "native-lifecycle-tests"))]
#[path = "../tests/support/native_lifecycle.rs"]
mod native_lifecycle;
#[cfg(all(test, feature = "native-lifecycle-tests"))]
mod test_hooks;
