# ever-connect-contracts

The wire contracts between an installation of an Ever product and Ever Platform, for Rust:
request and response types generated from the instance-facing API description, types of the JSON
Schemas (statistics report, entitlement document, consent record, key manifest, usage report, the
event feed), and the contract files themselves (`constants()`, `integrations()`,
`outbound_calls()`, the `schema_*` accessors), embedded and parsed on first use.

Dependencies: `serde` and `serde_json` only. The types carry no validation: validate a document
against its schema (the `ever-connect-sdk` crate does, for the documents it verifies) before
trusting it.
