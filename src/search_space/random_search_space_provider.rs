use crate::search_space::SearchSpace;
use crate::SearchSpaceProvider;
use num_bigint::{BigUint, RandBigInt};
use std::ops::Add;

pub struct RandomSearchSpaceProvider {}

impl RandomSearchSpaceProvider {
    pub fn new() -> RandomSearchSpaceProvider {
        RandomSearchSpaceProvider {}
    }
}

impl SearchSpaceProvider for RandomSearchSpaceProvider {
    fn next(&self) -> SearchSpace {
        let mut rng = rand::thread_rng();
        let start_inclusive: BigUint = rng.gen_biguint(256);
        let number_of_keys: u64 = 0_800_000;
        let number_of_keys = BigUint::from(number_of_keys);
        let end_exclusive = start_inclusive.clone().add(&number_of_keys);

        SearchSpace {
            start_inclusive,
            end_exclusive,
        }
    }

    fn done(&mut self, _search_space: &SearchSpace) {
        //ignore
    }
}
