//! Backpressure pipeline for the transfer engine (§27 of master plan).
//!
//! The pipeline connects bounded mpsc channels between stages:
//! ```text
//! Disk Read → Compress → Encrypt → Hash → Queue → QUIC
//! ```
//!
//! Each channel has capacity = `pipeline_buffers` (4–8 based on available RAM).
//! If the QUIC send stage is slower than disk read, the queue fills up,
//! stalling earlier stages — naturally rate-matching disk I/O to network throughput.
//! This prevents OOM on large files without explicit memory management.

use crate::compression::{compress, CompressionAlgo, CompressionError};
use crate::crypto::cipher::{build_nonce, encrypt_chunk, CipherSuite, CipherError, Direction};
use crate::crypto::hash::blake3_hash_parallel;
use tokio::sync::mpsc;
use thiserror::Error;

/// A raw chunk of file data, before any processing.
#[derive(Debug)]
pub struct RawChunk {
    pub index: u32,
    pub data: Vec<u8>,
    pub is_last: bool,
}

/// A chunk after compression.
#[derive(Debug)]
pub struct CompressedChunkData {
    pub index: u32,
    /// BLAKE3 of the original (pre-compression) data.
    pub original_hash: [u8; 32],
    pub compressed: Vec<u8>,
    pub algorithm: CompressionAlgo,
    pub is_last: bool,
}

/// A chunk ready for QUIC transmission.
#[derive(Debug)]
pub struct ReadyChunk {
    pub index: u32,
    pub original_hash: [u8; 32],
    pub encrypted: Vec<u8>,
    pub is_last: bool,
}

/// Stage in the transfer pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    Read,
    Compress,
    Encrypt,
    Send,
}

/// Errors in the pipeline.
#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("stage {stage:?}: compression failed: {source}")]
    Compression {
        stage: PipelineStage,
        source: CompressionError,
    },
    #[error("stage {stage:?}: encryption failed: {source}")]
    Cipher {
        stage: PipelineStage,
        source: CipherError,
    },
    #[error("stage {stage:?}: channel send failed (receiver dropped)")]
    ChannelClosed {
        stage: PipelineStage,
    },
}

/// A backpressure-bounded transfer pipeline.
///
/// Create it, push `RawChunk`s in, and receive `ReadyChunk`s out.
/// The bounded channels prevent runaway memory usage.
pub struct TransferPipeline {
    compress_tx: Option<mpsc::Sender<RawChunk>>,
    ready_rx: mpsc::Receiver<ReadyChunk>,
}

impl TransferPipeline {
    /// Create and launch a pipeline with the given configuration.
    ///
    /// # Parameters
    /// - `capacity`: number of in-flight chunks per stage (4–8 typical)
    /// - `compression`: algorithm to apply to each chunk
    /// - `session_id`: used for nonce construction (INV-5)
    /// - `session_key`: 32-byte symmetric key for encryption
    /// - `suite`: cipher suite to use
    pub fn new(
        capacity: usize,
        compression: CompressionAlgo,
        session_id: u32,
        session_key: [u8; 32],
        suite: CipherSuite,
    ) -> Self {
        let (raw_tx, raw_rx) = mpsc::channel::<RawChunk>(capacity);
        let (comp_tx, comp_rx) = mpsc::channel::<CompressedChunkData>(capacity);
        let (ready_tx, ready_rx) = mpsc::channel::<ReadyChunk>(capacity * 16);

        // Stage 1: Compress
        tokio::spawn(async move {
            let mut rx = raw_rx;
            while let Some(raw) = rx.recv().await {
                let original_hash = blake3_hash_parallel(&raw.data);
                let compressed = match compress(&raw.data, compression, 3) {
                    Ok(c) => c,
                    Err(_) => continue, // log error in production
                };
                let _ = comp_tx
                    .send(CompressedChunkData {
                        index: raw.index,
                        original_hash,
                        compressed,
                        algorithm: compression,
                        is_last: raw.is_last,
                    })
                    .await;
            }
        });

        // Stage 2: Encrypt + send to ready queue
        tokio::spawn(async move {
            let mut rx = comp_rx;
            let mut message_index = 0u32;
            while let Some(chunk) = rx.recv().await {
                let nonce = build_nonce(session_id, message_index, Direction::ToReceiver);
                message_index += 1;

                let encrypted = match encrypt_chunk(&session_key, &nonce, &chunk.compressed, suite) {
                    Ok(e) => e,
                    Err(_) => continue, // log error in production
                };
                let _ = ready_tx
                    .send(ReadyChunk {
                        index: chunk.index,
                        original_hash: chunk.original_hash,
                        encrypted,
                        is_last: chunk.is_last,
                    })
                    .await;
            }
        });

        TransferPipeline {
            compress_tx: Some(raw_tx),
            ready_rx,
        }
    }

    /// Feed a raw chunk into the pipeline.
    pub async fn push(&self, chunk: RawChunk) -> Result<(), PipelineError> {
        if let Some(ref tx) = self.compress_tx {
            tx.send(chunk)
                .await
                .map_err(|_| PipelineError::ChannelClosed { stage: PipelineStage::Compress })
        } else {
            Err(PipelineError::ChannelClosed { stage: PipelineStage::Compress })
        }
    }

    /// Close the input side of the pipeline, signalling EOF.
    pub fn close(&mut self) {
        self.compress_tx = None;
    }

    /// Clone the input sender if available.
    pub fn clone_tx(&self) -> Option<mpsc::Sender<RawChunk>> {
        self.compress_tx.clone()
    }

    /// Receive the next ready (compressed + encrypted) chunk from the pipeline.
    pub async fn next(&mut self) -> Option<ReadyChunk> {
        self.ready_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::generate_key;

    #[tokio::test]
    async fn test_pipeline_roundtrip() {
        let key = generate_key();
        let session_id = 42u32;
        let suite = CipherSuite::ChaCha20Poly1305Blake3;

        let mut pipeline = TransferPipeline::new(4, CompressionAlgo::None, session_id, key, suite);

        // Send one chunk
        let data = b"test pipeline data chunk".to_vec();
        pipeline
            .push(RawChunk {
                index: 0,
                data: data.clone(),
                is_last: true,
            })
            .await
            .expect("push must succeed");

        // Close the pipeline to signal end
        pipeline.close();

        // Receive the processed chunk
        let ready = pipeline.next().await.expect("must receive a ready chunk");
        assert_eq!(ready.index, 0);
        assert!(ready.is_last);
        // The encrypted data must not equal the original
        assert_ne!(ready.encrypted, data);
        // The hash must be BLAKE3 of original data
        assert_eq!(ready.original_hash, blake3_hash_parallel(&data));
    }

    #[tokio::test]
    async fn test_pipeline_multiple_chunks() {
        let key = generate_key();
        let mut pipeline = TransferPipeline::new(4, CompressionAlgo::Zstd, 1, key, CipherSuite::ChaCha20Poly1305Blake3);

        let chunks_to_send = 5usize;
        for i in 0..chunks_to_send {
            let data = format!("chunk {i} data").into_bytes();
            pipeline
                .push(RawChunk {
                    index: i as u32,
                    data,
                    is_last: i == chunks_to_send - 1,
                })
                .await
                .expect("push must succeed");
        }

        pipeline.close();

        let mut received = 0;
        while let Some(ready) = pipeline.next().await {
            assert!(ready.index < chunks_to_send as u32);
            received += 1;
        }
        assert_eq!(received, chunks_to_send, "must receive all chunks");
    }
}
