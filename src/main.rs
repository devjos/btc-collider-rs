#![feature(slice_as_chunks)]
#![feature(map_first_last)]

mod address_file;
mod btc_address;
mod collider;
mod hash_util;
mod key_util;
mod search_space;
mod wif;

use crate::search_space::file_search_space_provider::FileSearchSpaceProvider;
use crate::search_space::random_search_space_provider::RandomSearchSpaceProvider;
use crate::search_space::SearchSpaceProvider;
use chrono::{DateTime, Utc};
use clap::Parser;
use log::{debug, info, LevelFilter};
use secp256k1::Secp256k1;
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode, WriteLogger};
use std::fs::File;
use std::sync::{Arc, RwLock};
use std::thread;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    random: bool,
}

fn main() {
    init_logging();

    let args = Args::parse();
    let random = args.random;

    info!("Start btc-collider-rs");

    let hashes = address_file::read_addresses_file("addresses/latest.txt.gz");
    let hashes = Arc::new(RwLock::new(hashes));
    let secp = Arc::new(RwLock::new(Secp256k1::new()));
    let search_space_provider: Box<dyn SearchSpaceProvider> = if random {
        Box::new(RandomSearchSpaceProvider::new())
    } else {
        Box::new(FileSearchSpaceProvider::new("searchspace/done.txt"))
    };

    let search_space_provider = Arc::new(RwLock::new(search_space_provider));
    let mut thread_handles = Vec::new();
    let num_threads = num_cpus::get();
    debug!("Start {} collider threads", num_threads);
    for _ in 0..num_threads {
        let hashes = hashes.clone();
        let secp = secp.clone();
        let search_space_provider = search_space_provider.clone();
        thread_handles.push(thread::spawn(move || {
            let hashes = hashes.read().unwrap();
            let search_space = search_space_provider.write().unwrap().next();
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

            for found_key in result.found_keys {
                info!(
                    "Collision found. Key {} in {}",
                    found_key.to_str_radix(16),
                    result.search_space
                );
            }
        }));
    }

    debug!("Waiting for threads to finish");
    for thread_handle in thread_handles {
        thread_handle.join().unwrap();
    }
    info!("Shutdown btc-collider-rs")
}

fn init_logging() {
    let now: DateTime<Utc> = Utc::now();
    let log_file = format!("log/{}.log", now.format("%Y-%m-%dT%H%M%S"));

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
            File::create(log_file).unwrap(),
        ),
    ])
    .unwrap();
}
