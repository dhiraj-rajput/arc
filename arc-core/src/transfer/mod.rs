//! File transfer engine: adaptive chunking and pipeline.

pub mod chunker;
pub mod discovery;
pub mod orchestrator;
pub mod pipeline;
pub mod resume;

pub use chunker::AdaptiveChunker;
pub use discovery::{DiscoveryManager, get_local_ips};
pub use orchestrator::{
    check_relay_status, ping_peer, run_pairing_receiver, run_pairing_sender, run_receiver,
    run_sender, run_stdin_sender,
};
pub use pipeline::TransferPipeline;
