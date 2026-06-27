//! End-to-end file transfer orchestrator with zero-knowledge signaling.
//! Refactored and split into transport, sender, and receiver submodules.

pub mod transport;
pub mod sender;
pub mod receiver;

pub use sender::{run_sender, run_stdin_sender};
pub use receiver::run_receiver;
pub use transport::{run_pairing_sender, run_pairing_receiver, check_relay_status, ping_peer};
