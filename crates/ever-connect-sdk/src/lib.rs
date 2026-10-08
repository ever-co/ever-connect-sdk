//! `ever-connect-sdk`: the Ever Platform client of an Ever product installation, and the pieces it
//! is built from, each behind a feature:
//!
//! * `client` (default): [`client::EverPlatformClient`], every call made over the generated
//!   operation table behind the egress guard, with the instance token in memory; the connect key
//!   and the client assertion ([`keys`], [`assertion`]). Without it the crate pulls no HTTP client.
//! * `entitlement`: the key manifest verifier ([`manifest`], [`keyset`]) and the entitlement
//!   document verifier ([`entitlement`]), the one implementation every product uses.
//! * `stats`: the anonymous statistics checks and signer ([`stats`]).
//! * `entitlement` or `stats`: the compact JWS helpers a product uses outside the client
//!   ([`jws`]): a signer pinned to EdDSA over Ed25519, and the claims of a document already
//!   verified.
//! * `lookup`: identifier normalisation (version 1) and the salted hash ([`lookup`]).
//! * `usage`: the `ever.usage.v1` reading validator ([`usage`]).
//! * `managed` (with `client`): the managed-operation runner ([`managed`]).
//!
//! The connect-code helpers ([`codes`]) are always there. Nothing runs at load time; no error,
//! `Debug` or `Display` output carries a token, an assertion, a key or a document.
#![forbid(unsafe_code)]

pub mod codes;
#[cfg(feature = "managed")]
pub mod managed;

#[cfg(any(feature = "entitlement", feature = "stats", feature = "lookup"))]
mod encoding;
#[cfg(feature = "schema")]
mod schema;

#[cfg(feature = "client")]
pub mod assertion;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "entitlement")]
pub mod entitlement;
#[cfg(feature = "entitlement")]
pub mod jcs;
#[cfg(any(feature = "entitlement", feature = "stats"))]
pub mod jws;
#[cfg(feature = "client")]
pub mod keys;
#[cfg(feature = "entitlement")]
pub mod keyset;
#[cfg(feature = "lookup")]
pub mod lookup;
#[cfg(feature = "entitlement")]
pub mod manifest;
#[cfg(feature = "stats")]
pub mod stats;
#[cfg(feature = "usage")]
pub mod usage;

pub use ever_connect_contracts as contracts;
