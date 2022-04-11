use crate::btc_address;
use crate::btc_address::BTCAddressType;
use flate2::read::GzDecoder;
use log::{debug, info};
use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::{BufRead, Read};
use std::time::SystemTime;

pub fn read_addresses_file(file_name: &str) -> HashSet<[u8; 20]> {
    let file = File::open(file_name).unwrap();

    let reader: Box<dyn Read> = Box::new(GzDecoder::new(file));

    let mut addresses_set = HashSet::new();
    //let mut addresses_set = HashSet::with_capacity(117440512);
    let start_time = SystemTime::now();
    for line in io::BufReader::new(reader).lines() {
        let line = line.unwrap();
        let line = line.trim();
        let address_type = btc_address::get_address_type(line);
        match address_type {
            BTCAddressType::P2PK => {
                addresses_set.insert(btc_address::p2pk_address_to_160_bit_hash(line))
            }
            BTCAddressType::P2SH => false,
            BTCAddressType::P2WPKH => {
                addresses_set.insert(btc_address::p2wpkh_address_to_160_bit_hash(line))
            }
            BTCAddressType::P2WSH => false,
            BTCAddressType::MISC => false,
        };
    }
    let end_time = SystemTime::now();
    let time_taken = end_time.duration_since(start_time).unwrap().as_secs_f32();

    info!(
        "Read {} bitcoin-addresses from {} in {:.2}s",
        addresses_set.len(),
        file_name,
        time_taken
    );
    debug!(
        "Addresses set elements={}, capacity={}",
        addresses_set.len(),
        addresses_set.capacity()
    );

    addresses_set
}

#[cfg(test)]
mod tests {
    use crate::address_file::read_addresses_file;
    use crate::btc_address;

    #[test]
    fn can_read_file() {
        let addresses_hashes = read_addresses_file("addresses/test.txt.gz");
        assert_eq!(1, addresses_hashes.len());

        let expected_hash =
            btc_address::p2pk_address_to_160_bit_hash("127NVqnjf8gB9BFAW2dnQeM6wqmy1gbGtv");
        assert!(addresses_hashes.contains(&expected_hash));
    }
}
