#![feature(slice_as_chunks)]

mod address_file;
mod btc_address;
mod collider;
mod hash_util;
mod key_util;
mod search_space;
mod wif;

use crate::search_space::random_search_space_provider::RandomSearchSpaceProvider;
use crate::search_space::SearchSpaceProvider;
use log::{debug, info, LevelFilter};
use ripemd160::digest::Output;
use secp256k1::Secp256k1;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode, WriteLogger};
use std::fs::File;
use std::sync::{Arc, RwLock};
use std::thread;

const NUM_THREADS: u32 = 4;

fn main() {
    init_logging();

    info!("Start btc-collider-rs");

    let hashes = address_file::read_addresses_file("addresses/latest.txt.gz");
    let hashes = Arc::new(RwLock::new(hashes));
    let secp = Arc::new(RwLock::new(Secp256k1::new()));
    let search_space_provider = Arc::new(RwLock::new(RandomSearchSpaceProvider::new()));

    let mut thread_handles = Vec::new();
    for _ in 0..NUM_THREADS {
        let hashes = hashes.clone();
        let secp = secp.clone();
        let search_space_provider = search_space_provider.clone();
        thread_handles.push(thread::spawn(move || {
            let hashes = hashes.read().unwrap();
            let search_space = search_space_provider.read().unwrap().next();
            let ctx = collider::ColliderContext {
                search_space,
                addresses: &hashes,
                secp: &secp.read().unwrap(),
            };
            let result = collider::run(ctx);

            search_space_provider
                .write()
                .unwrap()
                .done(&result.search_space);

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
