pub mod file_search_space_provider;
pub mod random_search_space_provider;

use num_bigint::BigUint;

#[derive(Debug, Clone)]
pub struct SearchSpace {
    pub start_inclusive: BigUint,
    pub end_exclusive: BigUint,
}

pub trait SearchSpaceProvider {
    fn next(&self) -> SearchSpace;
    fn done(&mut self, search_space: &SearchSpace);
}
