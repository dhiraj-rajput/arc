//! File transfer engine: adaptive chunking and pipeline.

pub mod chunker;
pub mod pipeline;
pub mod resume;
pub mod orchestrator;
pub mod discovery;

pub use chunker::AdaptiveChunker;
pub use pipeline::TransferPipeline;
pub use discovery::{get_local_ips, DiscoveryManager};
pub use orchestrator::{run_sender, run_stdin_sender, run_receiver, run_pairing_sender, run_pairing_receiver, check_relay_status, ping_peer};
