//! End-to-end file transfer orchestrator with zero-knowledge signaling.
//! Refactored and split into transport, sender, and receiver submodules.

pub mod receiver;
pub mod sender;
pub mod transport;

pub use receiver::run_receiver;
pub use sender::{run_sender, run_stdin_sender};
pub use transport::{check_relay_status, ping_peer, run_pairing_receiver, run_pairing_sender};
