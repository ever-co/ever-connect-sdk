//! `ever-connect-sdk`: the managed-operation runner products build their executor on, and (feature
//! `stats`, on by default) the anonymous statistics checks and signer. The client, the entitlement
//! verifier and the lookup hashing are added to this crate next; everything here stays.
#![forbid(unsafe_code)]

pub mod managed;
#[cfg(feature = "stats")]
pub mod stats;

pub use ever_connect_contracts as contracts;
