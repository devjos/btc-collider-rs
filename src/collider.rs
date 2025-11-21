use crate::collider::PointStrategy::{
    OriginalPoint, OriginalPointLambda, OriginalPointLambdaNegated, OriginalPointLambdaSquared,
    OriginalPointLambdaSquaredNegated, OriginalPointNegated,
};
use crate::search_space::SearchSpace;
use crate::wif::private_key_to_wif;
use crate::{hash_util, key_util};
use hex_literal::hex;
use log::info;
use num_bigint::BigUint;
use num_traits::{Euclid, One, ToPrimitive};
use primitive_types::H160;
use secp256k1::{All, PublicKey, Secp256k1};
use std::cell::LazyCell;
use std::collections::HashSet;
use std::ops::{Add, Mul, Sub};
use std::time::SystemTime;

pub struct Collider<'a> {
    pub addresses: &'a HashSet<H160>,
    pub secp: &'a Secp256k1<All>,
}

#[derive(Clone)]
pub struct ColliderContext {
    pub search_space: SearchSpace,
}

#[derive(Debug)]
pub struct FoundKey {
    pub key: BigUint,
    pub strategy: PointStrategy,
    pub compressed: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PointStrategy {
    OriginalPoint,
    OriginalPointNegated,
    OriginalPointLambda,
    OriginalPointLambdaNegated,
    OriginalPointLambdaSquared,
    OriginalPointLambdaSquaredNegated,
}

pub struct ColliderResult {
    pub search_space: SearchSpace,
    pub found_keys: Vec<FoundKey>,
}

impl Collider<'_> {
    const ONE: LazyCell<BigUint> = LazyCell::new(|| BigUint::one());
    const BETA: LazyCell<BigUint> = LazyCell::new(|| {
        BigUint::from_bytes_be(&hex!(
            "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"
        ))
    });
    const P: LazyCell<BigUint> = LazyCell::new(|| {
        BigUint::from_bytes_be(&hex!(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
        ))
    });

    pub fn run(&self, search_space: SearchSpace) -> ColliderResult {
        let mut current_key = search_space.start_inclusive.clone();
        let mut found_keys: Vec<FoundKey> = Vec::new();

        let start_time = SystemTime::now();
        while current_key.le(&search_space.end_exclusive) {
            let public_key_original = key_util::get_public_key_from_private_key_vec(
                current_key.to_bytes_be(),
                &self.secp,
            );

            //OriginalPoint
            self.search_public_key(
                &current_key,
                &public_key_original,
                &OriginalPoint,
                &mut found_keys,
            );

            //OriginalPointNegated
            let public_key_negated = public_key_original.negate(&self.secp);
            self.search_public_key(
                &current_key,
                &public_key_negated,
                &OriginalPointNegated,
                &mut found_keys,
            );

            //OriginalPointLambda
            let public_key_lambda = self.calc_public_key_lambda(&public_key_original);
            self.search_public_key(
                &current_key,
                &public_key_lambda,
                &OriginalPointLambda,
                &mut found_keys,
            );

            //OriginalPointLambdaNegated
            let public_key_lambda_negated = public_key_original.negate(&self.secp);
            self.search_public_key(
                &current_key,
                &public_key_lambda_negated,
                &OriginalPointLambdaNegated,
                &mut found_keys,
            );

            //OriginalPointLambdaSquared
            let public_key_lambda_squared = self.calc_public_key_lambda(&public_key_lambda);
            self.search_public_key(
                &current_key,
                &public_key_lambda_squared,
                &OriginalPointLambdaSquared,
                &mut found_keys,
            );

            //OriginalPointLambdaSquaredNegated
            let public_key_lambda_squared_negated = public_key_lambda_squared.negate(&self.secp);
            self.search_public_key(
                &current_key,
                &public_key_lambda_squared_negated,
                &OriginalPointLambdaSquaredNegated,
                &mut found_keys,
            );

            current_key = current_key.add(&*Self::ONE);
        }
        let end_time = SystemTime::now();
        let time_taken = end_time.duration_since(start_time).unwrap().as_millis() + 1;

        let keys_per_sec = search_space
            .end_exclusive
            .clone()
            .sub(&search_space.start_inclusive)
            .to_u128()
            .unwrap()
            * 1_000
            / time_taken;

        info!(
            "{} collisions for {} at {} keys/sec",
            found_keys.len(),
            search_space,
            keys_per_sec
        );

        ColliderResult {
            search_space,
            found_keys,
        }
    }

    fn search_public_key(
        &self,
        current_key: &BigUint,
        public_key: &PublicKey,
        point_strategy: &PointStrategy,
        found_keys: &mut Vec<FoundKey>,
    ) {
        let (compressed, uncompressed) = hash_util::hash_public_key(&public_key);

        if self.addresses.contains(&compressed) {
            let found_key = FoundKey {
                key: current_key.clone(),
                strategy: point_strategy.clone(),
                compressed: true,
            };
            Self::log_collision(&found_key);
            found_keys.push(found_key);
        }
        if self.addresses.contains(&uncompressed) {
            let found_key = FoundKey {
                key: current_key.clone(),
                strategy: point_strategy.clone(),
                compressed: false,
            };
            Self::log_collision(&found_key);
            found_keys.push(found_key);
        }
    }

    fn log_collision(found_key: &FoundKey) {
        info!(
            "Collision found for {:?}, {}. Key {}. WIF {}",
            found_key.strategy,
            if found_key.compressed {
                "compressed"
            } else {
                "uncompressed"
            },
            found_key.key.to_str_radix(16),
            private_key_to_wif(&found_key.key, found_key.compressed)
        )
    }

    fn calc_public_key_lambda(&self, public_key: &PublicKey) -> PublicKey {
        let x = BigUint::from_bytes_be(&public_key.serialize()[1..33]);
        let (_div, rem) = x.mul(&*Self::BETA).div_rem_euclid(&*Self::P);
        let negated_x = rem.to_bytes_be();
        let mut compressed: [u8; 33] = [0; 33];
        compressed[0] = public_key.serialize()[0];
        compressed[33 - negated_x.len()..33].copy_from_slice(&negated_x[0..negated_x.len()]);

        PublicKey::from_slice(&compressed).unwrap()
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
    use secp256k1::PublicKey;
    use std::str::FromStr;

    #[test]
    fn puzzle_transactions() {
        let addresses = read_addresses_file("addresses/puzzle_3_to_7.txt.gz");
        assert_eq!(5, addresses.len());

        let start_inclusive: u32 = 1;
        let start_inclusive = BigUint::from(start_inclusive);
        let end_exclusive: u32 = 100;
        let end_exclusive = BigUint::from(end_exclusive);

        let collider = Collider {
            addresses: &addresses,
            secp: &Secp256k1::new(),
        };

        let result = collider.run(SearchSpace {
            start_inclusive,
            end_exclusive,
        });

        assert_eq!(5, result.found_keys.len());
        let expected: [u32; 5] = [7, 8, 21, 49, 76];
        for i in 0..5 {
            assert_eq!(
                expected[i],
                result.found_keys.get(i).unwrap().key.to_u32().unwrap()
            )
        }
    }

    #[test]
    fn puzzle_transaction_69() {
        let addresses = read_addresses_file("addresses/puzzle_69.txt.gz");
        assert_eq!(1, addresses.len());

        let start_inclusive: BigUint = BigUint::from_str_radix("101d83275fb2bc7e00", 16).unwrap();
        let end_exclusive = start_inclusive.clone().add(BigUint::from(1024usize));

        let collider = Collider {
            addresses: &addresses,
            secp: &Secp256k1::new(),
        };

        let result = collider.run(SearchSpace {
            start_inclusive,
            end_exclusive,
        });

        assert_eq!(1, result.found_keys.len());
        let expected_key = BigUint::from_str_radix("101d83275fb2bc7e0c", 16).unwrap();
        assert_eq!(expected_key, result.found_keys.get(0).unwrap().key);
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
        assert_eq!(private_key, result.found_keys.get(0).unwrap().key);
        assert!(matches!(
            result.found_keys.get(0).unwrap().strategy,
            OriginalPoint
        ));
        assert_eq!(private_key, result.found_keys.get(1).unwrap().key);
        assert!(matches!(
            result.found_keys.get(1).unwrap().strategy,
            OriginalPoint
        ));
    }

    fn run_collider_test(private_key: BigUint, addresses: &HashSet<H160>) -> ColliderResult {
        let start_inclusive = private_key.clone();
        let end_exclusive = private_key.add(BigUint::one());

        let collider = Collider {
            addresses,
            secp: &Secp256k1::new(),
        };

        collider.run(SearchSpace {
            start_inclusive,
            end_exclusive,
        })
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
        assert_eq!(key, result.found_keys.get(0).unwrap().key);
        assert_eq!(
            hex_key,
            result.found_keys.get(0).unwrap().key.to_str_radix(16)
        );
    }

    #[parameterized( wif = {
    "KzNAqFvXDbxBwqHAgjVRZ91JW2TiJoGiqhECPywEbGAy6sPHxuZu",
    "Kx5wBqo2tSurrBG6JUGN21Y4fZcr7Kk7pU6SYURaLQch632smxDB",
    "L3h41LG9wora1onggMK4AhRVRCbvJUTxBS68fMLJyEaj2mTvbw1z",
    "L4WJoCREc8JdiU3YrU5NptiT7T44atcH7yA5CC6gXaXBwqnrX6MV",
    }, address = {
    "bc1qexq9hf40892cwnkxa84rnvqfk36fmzys9n9quq",
    "bc1qhrzgyz49gtx5fkfqcu7kwlw2c8se5cklam4ap2",
    "bc1qz7d38k4lve2zxc50kap7k5v7lqz6q9mc5kek32",
    "bc1qqqq49mw5zp95ps4d0kr4cqaa7cuv47r6adhk43"
    })]
    fn segwit_from_wif(wif: &str, address: &str) {
        let mut addresses = HashSet::new();
        addresses.insert(btc_address::p2wpkh_address_to_160_bit_hash(&address));
        let key = BigUint::from_bytes_be(&wif_to_private_key(wif));

        let result = run_collider_test(key.clone(), &addresses);

        assert_eq!(1, result.found_keys.len());
        assert_eq!(key, result.found_keys.get(0).unwrap().key);
        assert!(matches!(
            result.found_keys.get(0).unwrap().strategy,
            OriginalPoint
        ));
        assert_eq!(result.found_keys.get(0).unwrap().compressed, true);
        //assert_eq!(hex_key, result.found_keys.get(0).unwrap().to_str_radix(16));
    }

    #[parameterized( private_key = {
    "000000000000000000000000000000000000000000000000f7051f27b09112d4",
    "2924e3e5ac18fd894504878d4fd1820e71bd63cd9b15d69511926e5f05d99d3a",
    "d6db1c1a53e70276bafb7872b02e7df048f179191432c9a5b73ad10619cb9133",
    "fffffffffffffffffffffffffffffffebaaedce6af48a03ac8cd3f651fa52e6d",
    "d6db1c1a53e70276bafb7872b02e7df048f179191432c9a6ae3ff02dca5ca407",
    "2924e3e5ac18fd894504878d4fd1820e71bd63cd9b15d69608978d86b66ab00e",
    })]
    fn endomorphism(private_key: &str) {
        const PUBLIC_KEYS: [&str; 6] = [
            "02100611c54dfef604163b8358f7b7fac13ce478e02cb224ae16d45526b25d9d4d",
            "03100611c54dfef604163b8358f7b7fac13ce478e02cb224ae16d45526b25d9d4d",
            "03792bfa55bf659967951b21060c05c250cd261ec3ea02704815bfb1c5ccc800fd",
            "02792bfa55bf659967951b21060c05c250cd261ec3ea02704815bfb1c5ccc800fd",
            "0276cdf3e4f29b709454a95ba0fc4242edf5f5685be94b6b09d36bf91280da5de5",
            "0376cdf3e4f29b709454a95ba0fc4242edf5f5685be94b6b09d36bf91280da5de5",
        ];

        let mut addresses = HashSet::new();
        for public_key in PUBLIC_KEYS {
            let public_key = PublicKey::from_str(public_key).unwrap();
            let (compressed, uncompressed) = hash_util::hash_public_key(&public_key);
            addresses.insert(compressed);
            addresses.insert(uncompressed);
        }

        let private_key = BigUint::from_str_radix(&private_key, 16).unwrap();
        let result = run_collider_test(private_key.clone(), &addresses);

        for strategy in [
            OriginalPoint,
            OriginalPointNegated,
            OriginalPointLambda,
            OriginalPointLambdaNegated,
            OriginalPointLambdaSquared,
            OriginalPointLambdaSquaredNegated,
        ] {
            assert!(result
                .found_keys
                .iter()
                .find(|a| a.strategy == strategy && a.compressed)
                .is_some());
            assert!(result
                .found_keys
                .iter()
                .find(|a| a.strategy == strategy && !a.compressed)
                .is_some());
        }

        assert_eq!(12, result.found_keys.len());
    }
}
