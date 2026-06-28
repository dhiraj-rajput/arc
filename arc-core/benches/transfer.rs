#![allow(deprecated)]
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_blake3_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hashing");
    
    for size in [1024, 64 * 1024, 1024 * 1024, 16 * 1024 * 1024] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.bench_with_input(
            BenchmarkId::new("hash", format!("{}KB", size / 1024)),
            &data,
            |b, data| {
                b.iter(|| {
                    let hash = blake3::hash(data);
                    criterion::black_box(hash);
                });
            },
        );
    }
    group.finish();
}

fn bench_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression");
    
    // Generate compressible data (repeated pattern)
    let compressible: Vec<u8> = "Hello, World! This is a test string for compression benchmarks. "
        .repeat(16384)
        .into_bytes();
    
    // Generate incompressible data (random)
    let random: Vec<u8> = (0..compressible.len()).map(|i| {
        ((i * 1103515245 + 12345) >> 16) as u8
    }).collect();
    
    group.bench_function("zstd_compress_text", |b| {
        b.iter(|| {
            let compressed = zstd::encode_all(&compressible[..], 3).unwrap();
            criterion::black_box(compressed);
        });
    });
    
    group.bench_function("lz4_compress_text", |b| {
        b.iter(|| {
            let compressed = lz4_flex::compress_prepend_size(&compressible);
            criterion::black_box(compressed);
        });
    });
    
    group.bench_function("zstd_compress_random", |b| {
        b.iter(|| {
            let compressed = zstd::encode_all(&random[..], 3).unwrap();
            criterion::black_box(compressed);
        });
    });

    group.finish();
}

fn bench_encryption(c: &mut Criterion) {
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
    use chacha20poly1305::aead::generic_array::GenericArray;
    
    let mut group = c.benchmark_group("encryption");
    let key = [0x42u8; 32];
    let nonce_bytes = [0u8; 12];
    
    for size in [1024, 64 * 1024, 256 * 1024, 1024 * 1024] {
        let data: Vec<u8> = vec![0xAB; size];
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
        let nonce = GenericArray::from_slice(&nonce_bytes);
        
        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305", format!("{}KB", size / 1024)),
            &data,
            |b, data| {
                b.iter(|| {
                    let encrypted = cipher.encrypt(nonce, data.as_slice()).unwrap();
                    criterion::black_box(encrypted);
                });
            },
        );
    }
    group.finish();
}

fn bench_file_hash_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_hash_throughput");
    for size_mb in [1usize, 64] {
        let data: Vec<u8> = (0..size_mb * 1024 * 1024)
            .map(|i| (i % 256) as u8)
            .collect();
        group.bench_with_input(
            BenchmarkId::new("blake3_full", format!("{size_mb}MB")),
            &data,
            |b, data| {
                b.iter(|| {
                    let hash = blake3::hash(data);
                    criterion::black_box(hash);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_blake3_hashing, bench_compression, bench_encryption, bench_file_hash_throughput);
criterion_main!(benches);
