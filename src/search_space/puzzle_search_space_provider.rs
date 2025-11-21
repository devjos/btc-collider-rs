use crate::search_space::{SearchSpace, SearchSpaceProvider};
use num_bigint::{BigUint, RandBigInt};
use num_traits::pow;
use std::ops::Add;

pub struct PuzzleSearchSpaceProvider {
    lower_end: BigUint,
    upper_end: BigUint,
}

impl PuzzleSearchSpaceProvider {
    pub fn new(puzzle_number: usize) -> PuzzleSearchSpaceProvider {
        PuzzleSearchSpaceProvider {
            lower_end: BigUint::from(pow(2u128, puzzle_number - 1)),
            upper_end: BigUint::from(pow(2u128, puzzle_number)),
        }
    }
}

impl SearchSpaceProvider for PuzzleSearchSpaceProvider {
    fn next(&mut self) -> SearchSpace {
        let mut rng = rand::thread_rng();
        let start_inclusive: BigUint = rng.gen_biguint_range(&self.lower_end, &self.upper_end);
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
