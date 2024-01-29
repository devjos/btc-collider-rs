use btc_collider_rs::search_space::file_search_space_provider::FileSearchSpaceProvider;
use btc_collider_rs::search_space::random_search_space_provider::RandomSearchSpaceProvider;
use btc_collider_rs::search_space::SearchSpaceProvider;
use btc_collider_rs::{address_file, collider};
use chrono::{DateTime, Utc};
use clap::Parser;
use log::{debug, info, LevelFilter};
use primitive_types::H160;
use secp256k1::{All, Secp256k1};
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode, WriteLogger};
use std::collections::HashSet;
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Search randomly
    #[clap(short, long)]
    random: bool,

    /// Number of threads
    #[clap(long, default_value_t = num_cpus::get())]
    threads: usize,

    /// Run with time limit (in minutes)
    #[clap(short, long)]
    timeout: Option<u64>,
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

    info!("Start collider on {} threads", args.threads);
    let continue_search = Arc::new(AtomicBool::new(true));
    for _ in 0..args.threads {
        let hashes = hashes.clone();
        let secp = secp.clone();
        let search_space_provider = search_space_provider.clone();
        let continue_search = continue_search.clone();
        thread_handles.push(thread::spawn(move || {
            run_search(hashes, secp, search_space_provider, continue_search);
        }));
    }

    match args.timeout {
        Some(timeout) => {
            debug!("Sleep on main thread for {} minutes", timeout);
            thread::sleep(Duration::from_secs(timeout * 60));

            debug!("Set continue to false");
            continue_search.store(false, Ordering::Relaxed);
        }
        None => loop {
            debug!("Keep running until interrupted");
            thread::sleep(Duration::from_secs(3600));
        },
    }

    debug!("Waiting for threads to finish");
    for thread_handle in thread_handles {
        thread_handle.join().unwrap();
    }
    info!("Shutdown btc-collider-rs")
}

fn run_search(
    hashes: Arc<RwLock<HashSet<H160>>>,
    secp: Arc<RwLock<Secp256k1<All>>>,
    search_space_provider: Arc<RwLock<Box<dyn SearchSpaceProvider>>>,
    continue_search: Arc<AtomicBool>,
) {
    let hashes = hashes.read().unwrap();

    while continue_search.load(Ordering::Relaxed) {
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
    }
    debug!("Thread done");
}

fn init_logging() {
    let now: DateTime<Utc> = Utc::now();
    let log_file = format!("log/{}.log", now.format("%Y-%m-%dT%H%M%S"));

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
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
