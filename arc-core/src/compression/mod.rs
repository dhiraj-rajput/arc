//! Adaptive compression pipeline.
//!
//! # Strategy (§2.3 of master plan)
//!
//! Before committing to compression, arc samples the first 64 KiB of a file
//! and probes compressibility using a fast zstd level-1 trial compression.
//!
//! Decision table:
//! - Ratio < 1.05 → file is pre-compressed (JPEG, MP4, ZIP, etc.) → send raw
//! - Ratio > 1.30 → significant gain (text, code, JSON) → use zstd level 3
//! - Ratio 1.05–1.30 → marginal → try lz4 (faster, ~10 GB/s)
//!
//! Text/code transfers typically achieve 3–10× compression at ~5 GB/s (zstd level 3).
//! This alone can make a 100 MB source tree transfer in under a second on a LAN.

use bincode::{Decode, Encode};
use thiserror::Error;

/// Supported compression algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum CompressionAlgo {
    /// No compression (raw bytes).
    None = 0,
    /// Zstandard (best ratio/speed tradeoff). Default for compressible data.
    Zstd = 1,
    /// LZ4 (maximum speed, lower ratio). Used for marginally compressible data.
    Lz4 = 2,
}

/// Errors from compression/decompression.
#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("compression failed: {0}")]
    CompressFailed(String),
    #[error("decompression failed: {0}")]
    DecompressFailed(String),
}

/// Result of a compressibility probe.
#[derive(Debug, Clone)]
pub struct CompressibilityResult {
    /// The chosen algorithm (based on measured ratio).
    pub algorithm: CompressionAlgo,
    /// The measured compression ratio (1.0 = uncompressible, higher = more compressible).
    pub ratio: f32,
}

/// Probe the compressibility of a data sample.
///
/// Takes up to the first 64 KiB of data and performs a trial zstd level-1 compression.
/// Returns the algorithm to use for the full file transfer.
///
/// # Performance
///
/// zstd level-1 runs at ~8 GB/s, so probing 64 KiB takes < 1 ms.
pub fn probe_compressibility(sample: &[u8]) -> CompressibilityResult {
    const SAMPLE_SIZE: usize = 64 * 1024;
    let probe = &sample[..sample.len().min(SAMPLE_SIZE)];

    if probe.is_empty() {
        return CompressibilityResult {
            algorithm: CompressionAlgo::None,
            ratio: 1.0,
        };
    }

    // Trial compression at zstd level 1 (fastest, ~8 GB/s)
    let compressed = match zstd::bulk::compress(probe, 1) {
        Ok(c) => c,
        Err(_) => {
            return CompressibilityResult {
                algorithm: CompressionAlgo::None,
                ratio: 1.0,
            };
        }
    };

    let ratio = probe.len() as f32 / compressed.len() as f32;

    let algorithm = match ratio {
        r if r < 1.05 => CompressionAlgo::None, // pre-compressed: skip
        r if r > 1.30 => CompressionAlgo::Zstd, // significant gain: use zstd
        _ => CompressionAlgo::Lz4,              // marginal: use lz4 (faster)
    };

    CompressibilityResult { algorithm, ratio }
}

/// Compress data with the specified algorithm.
///
/// `level` is only used for `Zstd` (1–22; level 3 is the recommended default).
pub fn compress(
    data: &[u8],
    algo: CompressionAlgo,
    level: i32,
) -> Result<Vec<u8>, CompressionError> {
    match algo {
        CompressionAlgo::None => Ok(data.to_vec()),
        CompressionAlgo::Zstd => {
            let clamped_level = level.clamp(1, 22);
            zstd::bulk::compress(data, clamped_level)
                .map_err(|e| CompressionError::CompressFailed(e.to_string()))
        }
        CompressionAlgo::Lz4 => Ok(lz4_flex::compress_prepend_size(data)),
    }
}

/// Decompress data that was compressed with the specified algorithm.
pub fn decompress(data: &[u8], algo: CompressionAlgo) -> Result<Vec<u8>, CompressionError> {
    decompress_with_limit(data, algo, 100 * 1024 * 1024)
}

/// Decompress data with a specified output size limit.
pub fn decompress_with_limit(
    data: &[u8],
    algo: CompressionAlgo,
    max_size: usize,
) -> Result<Vec<u8>, CompressionError> {
    match algo {
        CompressionAlgo::None => {
            if data.len() > max_size {
                return Err(CompressionError::DecompressFailed(
                    "decompressed size limit exceeded".to_string(),
                ));
            }
            Ok(data.to_vec())
        }
        CompressionAlgo::Zstd => {
            let limit = match zstd::zstd_safe::get_frame_content_size(data) {
                Ok(Some(sz)) if sz as usize <= max_size => sz as usize,
                _ => max_size,
            };
            zstd::bulk::decompress(data, limit)
                .map_err(|e| CompressionError::DecompressFailed(e.to_string()))
        }
        CompressionAlgo::Lz4 => {
            if data.len() < 4 {
                return Err(CompressionError::DecompressFailed(
                    "invalid compressed data".to_string(),
                ));
            }
            let uncompressed_size = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
            if uncompressed_size > max_size {
                return Err(CompressionError::DecompressFailed(
                    "decompressed size limit exceeded".to_string(),
                ));
            }
            let decompressed = lz4_flex::decompress_size_prepended(data)
                .map_err(|e| CompressionError::DecompressFailed(e.to_string()))?;
            Ok(decompressed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_zstd() {
        let data = b"hello arc, this is some compressible text data that repeats. \
                     hello arc, this is some compressible text data that repeats.";
        let compressed = compress(data, CompressionAlgo::Zstd, 3).expect("zstd compress");
        let decompressed = decompress(&compressed, CompressionAlgo::Zstd).expect("zstd decompress");
        assert_eq!(decompressed, data);
        // Text should compress
        assert!(
            compressed.len() < data.len(),
            "text should be smaller after zstd"
        );
    }

    #[test]
    fn test_compress_decompress_lz4() {
        let data = b"lz4 test data that is compressible because it repeats a lot. \
                     lz4 test data that is compressible because it repeats a lot.";
        let compressed = compress(data, CompressionAlgo::Lz4, 0).expect("lz4 compress");
        let decompressed = decompress(&compressed, CompressionAlgo::Lz4).expect("lz4 decompress");
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_none() {
        let data = b"raw data, no compression";
        let out = compress(data, CompressionAlgo::None, 0).expect("none compress");
        let back = decompress(&out, CompressionAlgo::None).expect("none decompress");
        assert_eq!(out, data);
        assert_eq!(back, data);
    }

    #[test]
    fn test_probe_text_uses_zstd() {
        // Highly compressible text
        let text = "the quick brown fox jumps over the lazy dog. ".repeat(2000);
        let result = probe_compressibility(text.as_bytes());
        assert_eq!(
            result.algorithm,
            CompressionAlgo::Zstd,
            "highly compressible text should use zstd, ratio was {}",
            result.ratio
        );
        assert!(result.ratio > 1.30, "text ratio should be > 1.30");
    }

    #[test]
    fn test_probe_random_uses_none() {
        // Random data (like JPEG / MP4 / ZIP content) → not compressible
        let mut data = vec![0u8; 64 * 1024];
        for byte in &mut data {
            *byte = rand::random();
        }
        let result = probe_compressibility(&data);
        // Random data should probe as None or Lz4 (ratio ≈ 1.0)
        assert!(
            result.ratio < 1.1,
            "random data should have ratio < 1.1, got {}",
            result.ratio
        );
    }

    #[test]
    fn test_probe_empty() {
        let result = probe_compressibility(&[]);
        assert_eq!(result.algorithm, CompressionAlgo::None);
    }

    #[test]
    fn test_roundtrip_all_algorithms() {
        let data = b"test data for all algorithm roundtrips";
        for algo in [
            CompressionAlgo::None,
            CompressionAlgo::Zstd,
            CompressionAlgo::Lz4,
        ] {
            let compressed =
                compress(data, algo, 3).unwrap_or_else(|e| panic!("{algo:?} compress failed: {e}"));
            let decompressed = decompress(&compressed, algo)
                .unwrap_or_else(|e| panic!("{algo:?} decompress failed: {e}"));
            assert_eq!(decompressed.as_slice(), data, "{algo:?} roundtrip failed");
        }
    }

    #[test]
    fn test_decompression_bomb_zstd() {
        let data = vec![0u8; 1000];
        let compressed = compress(&data, CompressionAlgo::Zstd, 3).unwrap();
        // Decompressing with limit smaller than data length should fail
        let res = decompress_with_limit(&compressed, CompressionAlgo::Zstd, 500);
        assert!(res.is_err(), "zstd decompression bomb must fail");
    }

    #[test]
    fn test_decompression_bomb_lz4() {
        let data = vec![0u8; 1000];
        let compressed = compress(&data, CompressionAlgo::Lz4, 0).unwrap();
        // Decompressing with limit smaller than data length should fail
        let res = decompress_with_limit(&compressed, CompressionAlgo::Lz4, 500);
        assert!(res.is_err(), "lz4 decompression bomb must fail");

        // Test invalid lz4 data smaller than 4 bytes
        assert!(decompress_with_limit(&[0u8; 3], CompressionAlgo::Lz4, 100).is_err());
    }
}
