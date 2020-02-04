use criterion::{criterion_group, criterion_main, Criterion};
use sig_server::util::{serialize_txns_in_parallel, serialize_txns};
use rand;

fn get_txns() -> Vec<Vec<u8>> {
    // Not accepting count or txn size to avoid accidentally check with different data
    let count = 1000;
    let txn_size = 200;
    let mut txns = vec![];
    for _ in 0..count {
        let txn_bytes: Vec<u8> = (0..txn_size).map(|_| { rand::random::<u8>() }).collect();
        txns.push(txn_bytes);
    }
    txns
}

/// Benchmark parallel txn serialization
#[no_mangle]
fn base64_benchmark_parallel(c: &mut Criterion) {
    let txns= get_txns();

    c.bench_function(format!("Serialize in parallel").as_str(),  |b| {
        b.iter(|| serialize_txns_in_parallel(&txns));
    });
}

/// Benchmark sequential txn serialization
#[no_mangle]
fn base64_benchmark_sequential(c: &mut Criterion) {
    let txns= get_txns();

    c.bench_function(format!("Serialize sequentially").as_str(),  |b| {
        b.iter(|| serialize_txns(&txns));
    });
}


criterion_group!(benches, base64_benchmark_parallel, base64_benchmark_sequential);
criterion_main!(benches);