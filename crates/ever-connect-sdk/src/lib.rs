//! `ever-connect-sdk` (skeleton): the managed-operation runner products build their executor on.
//! The client, the entitlement verifier, the statistics signer and the lookup hashing are added to
//! this crate next; everything here stays.
#![forbid(unsafe_code)]

pub mod managed;

pub use ever_connect_contracts as contracts;
