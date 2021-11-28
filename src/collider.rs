use crate::search_space::SearchSpace;
use crate::{hash_util, key_util};
use log::info;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
use secp256k1::{All, Secp256k1};
use std::collections::HashSet;
use std::ops::{Add, Sub};
use std::time::SystemTime;

pub struct ColliderContext<'a> {
    pub search_space: SearchSpace,
    pub addresses: &'a HashSet<[u8; 20]>,
    pub secp: &'a Secp256k1<All>,
}

pub struct ColliderResult {
    pub search_space: SearchSpace,
    pub found_keys: Vec<BigUint>,
}

pub fn run(ctx: ColliderContext) -> ColliderResult {
    let mut current_key = ctx.search_space.start_inclusive.clone();
    let mut found_keys: Vec<BigUint> = Vec::new();

    let start_time = SystemTime::now();
    while current_key.le(&ctx.search_space.end_exclusive) {
        let public_key =
            key_util::get_public_key_from_private_key_vec(current_key.to_bytes_be(), &ctx.secp);
        let (compressed, uncompressed) = hash_util::hash_public_key(&public_key);

        if ctx.addresses.contains(&compressed) {
            info!("Found collision: {}", current_key.to_str_radix(16));
            found_keys.push(current_key.clone());
        }
        if ctx.addresses.contains(&uncompressed) {
            info!("Found collision: {}", current_key.to_str_radix(16));
            found_keys.push(current_key.clone());
        }

        current_key = current_key.add(BigUint::one());
    }
    let end_time = SystemTime::now();
    let time_taken = end_time.duration_since(start_time).unwrap().as_secs() + 1;

    let keys_per_sec = ctx
        .search_space
        .end_exclusive
        .clone()
        .sub(&ctx.search_space.start_inclusive.clone())
        .to_u64()
        .unwrap()
        / time_taken;

    info!(
        "{} collisions for {} at {} keys/sec",
        found_keys.len(),
        ctx.search_space,
        keys_per_sec
    );

    ColliderResult {
        search_space: ctx.search_space,
        found_keys,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_file::read_addresses_file;
    use crate::btc_address;
    use crate::wif::wif_to_private_key;
    use num_traits::{Num, ToPrimitive};
    use parameterized_macro::parameterized;
    use std::ops::Sub;

    #[test]
    fn puzzle_transactions() {
        let addresses = read_addresses_file("addresses/puzzle_3_to_7.txt.gz");
        assert_eq!(5, addresses.len());

        let start_inclusive: u32 = 1;
        let start_inclusive = BigUint::from(start_inclusive);
        let end_exclusive: u32 = 100;
        let end_exclusive = BigUint::from(end_exclusive);

        let ctx = ColliderContext {
            search_space: SearchSpace {
                start_inclusive,
                end_exclusive,
            },
            addresses: &addresses,
            secp: &Secp256k1::new(),
        };

        let result = run(ctx);

        assert_eq!(5, result.found_keys.len());
        let expected: [u32; 5] = [7, 8, 21, 49, 76];
        for i in 0..5 {
            assert_eq!(
                expected[i],
                result.found_keys.get(i).unwrap().to_u32().unwrap()
            )
        }
    }

    #[parameterized( wif = {
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEt3BU5TJooQ",
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB4gHj2LY81dM4N",
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5mG3VbvRiMXFMAi2euC7",
    "5HpHagT65TZzG1PH3CSu63k8DbpvD8sovht9C5oEoZSk2JTBpU4",
    "5Km2kuu7vtFDPpxywn4u3NLpbr5jKpTB3jsuDU2KYEqeHZGfNdG",
    })]
    fn can_find_keys(wif: &str) {
        let file = format!("addresses/wif/{}.txt.gz", wif);
        let addresses = read_addresses_file(&file);
        assert_eq!(2, addresses.len());

        let private_key = wif_to_private_key(wif);
        let result = run_collider_test(BigUint::from_bytes_be(&private_key), &addresses);

        assert_eq!(2, result.found_keys.len());

        let private_key = BigUint::from_bytes_be(&private_key);
        assert_eq!(private_key, *result.found_keys.get(0).unwrap());
        assert_eq!(private_key, *result.found_keys.get(1).unwrap());
    }

    fn run_collider_test(private_key: BigUint, addresses: &HashSet<[u8; 20]>) -> ColliderResult {
        let search_space: u32 = 5;
        let search_space = BigUint::from(search_space);
        let start_inclusive = private_key.clone().sub(&search_space);
        let end_exclusive = private_key.add(&search_space);

        let ctx = ColliderContext {
            search_space: SearchSpace {
                start_inclusive,
                end_exclusive,
            },
            addresses,
            secp: &Secp256k1::new(),
        };

        run(ctx)
    }

    #[parameterized( hex_key = {
    "e006ce0cd8acb8a99a721a92e6c23671e8490477e18274bfd2f18eebb20c71a8",
    "bdb70c7043798cc7d717a32a64ff597839bc2ed1a83c5a4eaa5873c83cefb589",
    "f2afe7fc3d6e219652a736e33f84eac2dd0f8558a0d4177c3924d43fce5902ac",
    }, address = {
    "bc1qfxxmpaq6khkjfd5t5a8l37x5c6fs6prny7xyh7",
    "bc1q0vww3g0w2325jwft3ypr95edy6nz3na9kw7eum",
    "bc1qa3kkplcah8jrn7uj0xjrvydhpmx3cxqw3uzx45",
    })]
    fn segwit(hex_key: &str, address: &str) {
        let mut addresses = HashSet::new();
        addresses.insert(btc_address::p2wpkh_address_to_160_bit_hash(&address));
        let key = BigUint::from_str_radix(&hex_key, 16).unwrap();

        let result = run_collider_test(key.clone(), &addresses);

        assert_eq!(1, result.found_keys.len());
        assert_eq!(key, *result.found_keys.get(0).unwrap());
        assert_eq!(hex_key, result.found_keys.get(0).unwrap().to_str_radix(16));
    }
}
