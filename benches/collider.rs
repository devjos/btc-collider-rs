use btc_collider_rs::collider::ColliderContext;
use btc_collider_rs::search_space::SearchSpace;
use btc_collider_rs::{collider, hash_util, key_util};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_bigint::BigUint;
use secp256k1::{All, PublicKey, Secp256k1};
use std::collections::HashSet;

fn criterion_benchmark(c: &mut Criterion) {
    let secp = Secp256k1::new();
    let addresses = HashSet::new();

    let start: u64 = 1;
    let search_space = SearchSpace {
        start_inclusive: BigUint::from(start),
        end_exclusive: BigUint::from(start + 1000),
    };

    let ctx = ColliderContext {
        search_space,
        addresses: &addresses,
        secp: &secp,
    };

    c.bench_function("collider", |b| {
        b.iter(|| collider::run(black_box(ctx.clone())))
    });

    let secret_key: u32 = 1;
    let public_key = key_util::get_public_key_from_private_key_vec(
        BigUint::from(secret_key).to_bytes_be(),
        &ctx.secp,
    );
    c.bench_function("hash", |b| {
        b.iter(|| hash_util::hash_public_key(black_box(&public_key)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
