#![feature(slice_as_chunks)]

mod address_file;
mod btc_address;
mod collider;
mod hash_util;
mod key_util;
mod wif;

use log::{debug, info, LevelFilter};
use num_bigint::{BigUint, RandBigInt};
use ripemd160::digest::Output;
use secp256k1::Secp256k1;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode, WriteLogger};
use std::fs::File;
use std::ops::Add;
use std::sync::{Arc, RwLock};
use std::thread;

const NUM_THREADS: u32 = 4;

fn main() {
    init_logging();

    info!("Start btc-collider-rs");

    let hashes = address_file::read_addresses_file("addresses/latest.txt.gz");
    let hashes = Arc::new(RwLock::new(hashes));
    let secp = Arc::new(RwLock::new(Secp256k1::new()));

    let mut thread_handles = Vec::new();
    for _ in 0..NUM_THREADS {
        let hashes = hashes.clone();
        let secp = secp.clone();
        thread_handles.push(thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let start_inclusive: BigUint = rng.gen_biguint(256);
            let number_of_keys: u64 = 0_800_000;
            let number_of_keys = BigUint::from(number_of_keys);
            let end_exclusive = start_inclusive.clone().add(&number_of_keys);

            let hashes = hashes.read().unwrap();
            let ctx = collider::ColliderContext {
                start_inclusive,
                end_exclusive,
                addresses: &hashes,
                secp: &secp.read().unwrap(),
            };
            let result = collider::run(ctx);

            info!("foundKeys={:?}", result.found_keys);
        }));
    }

    debug!("Waiting for threads to finish");
    for thread_handle in thread_handles {
        thread_handle.join().unwrap();
    }
    info!("Shutdown btc-collider-rs")
}

fn init_logging() {
    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Debug,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Info,
            Config::default(),
            File::create("btc-collider-rs.log").unwrap(),
        ),
    ])
    .unwrap();
}
