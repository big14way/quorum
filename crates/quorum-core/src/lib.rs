//! quorum-core: a pure Rust, wasm32-wasip2 friendly Solana substrate for
//! ZeroClaw tool plugins. No solana-sdk, no async runtime, no wasm deps in
//! this crate; transport is abstracted behind the Rpc trait so every consumer
//! is host-testable with `cargo test` and a mock.
//!
//! Built for the Quorum suite (squads-propose, squads-watch, tx-xray), and
//! usable by any other plugin that needs Solana bytes over plain HTTP.

pub mod message;
pub mod policy;
pub mod pubkey;
pub mod receipt;
pub mod rpc;
pub mod spl;
pub mod squads;
