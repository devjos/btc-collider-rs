pub mod file_search_space_provider;
pub mod puzzle_search_space_provider;
pub mod random_search_space_provider;

use num_bigint::BigUint;
use num_traits::Num;
use std::fmt::{Display, Formatter};

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct SearchSpace {
    pub start_inclusive: BigUint,
    pub end_exclusive: BigUint,
}

pub trait SearchSpaceProvider: Sync + Send {
    fn next(&mut self) -> SearchSpace;
    fn done(&mut self, search_space: &SearchSpace);
}

impl SearchSpace {
    pub fn from_line(line: &str) -> SearchSpace {
        let splitted = line.split("-").collect::<Vec<_>>();
        if splitted.len() != 2 {
            panic!("Line must be of format <number>-<number>");
        }

        let start_inclusive = BigUint::from_str_radix(splitted.get(0).unwrap(), 16).unwrap();
        let end_exclusive = BigUint::from_str_radix(splitted.get(1).unwrap(), 16).unwrap();

        SearchSpace {
            start_inclusive,
            end_exclusive,
        }
    }

    fn can_merge(&self, other: &SearchSpace) -> bool {
        let compared = self.start_inclusive.cmp(&other.start_inclusive);
        if compared.is_lt() {
            return self.end_exclusive.cmp(&other.start_inclusive).is_ge();
        } else if compared.is_eq() {
            return true;
        } else {
            return self.start_inclusive.cmp(&other.end_exclusive).is_le();
        }
    }

    fn merge(&self, other: &SearchSpace) -> SearchSpace {
        if self.can_merge(other) {
            SearchSpace {
                start_inclusive: self
                    .start_inclusive
                    .clone()
                    .min(other.start_inclusive.clone()),
                end_exclusive: self.end_exclusive.clone().max(other.end_exclusive.clone()),
            }
        } else {
            panic!("Cannot merge");
        }
    }
}

impl Display for SearchSpace {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:0>64}-{:0>64}",
            self.start_inclusive.to_str_radix(16),
            self.end_exclusive.to_str_radix(16)
        )
    }
}

#[cfg(test)]
mod test {
    use crate::search_space::SearchSpace;
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;
    use parameterized_macro::parameterized;

    #[parameterized( values = {
        [1, 2, 2, 10],
        [1, 5, 2, 10],
        [1, 2, 5, 10],
        [1, 10, 3, 5],
        [3, 5, 1, 10],
    }, can_merge = {
        true, true, false, true, true,
    }, expected_merge = {
        [1, 10],
        [1, 10],
        [0, 0],
        [1, 10],
        [1, 10],
    })]
    fn can_merge(values: [u64; 4], can_merge: bool, expected_merge: [u64; 2]) {
        let s1 = SearchSpace {
            start_inclusive: BigUint::from(values[0]),
            end_exclusive: BigUint::from(values[1]),
        };
        let s2 = SearchSpace {
            start_inclusive: BigUint::from(values[2]),
            end_exclusive: BigUint::from(values[3]),
        };

        assert_eq!(can_merge, s1.can_merge(&s2));
        assert_eq!(can_merge, s2.can_merge(&s1));

        if can_merge {
            let mut merged = s1.merge(&s2);
            assert_eq!(expected_merge[0], merged.start_inclusive.to_u64().unwrap());
            assert_eq!(expected_merge[1], merged.end_exclusive.to_u64().unwrap());

            merged = s2.merge(&s1);
            assert_eq!(expected_merge[0], merged.start_inclusive.to_u64().unwrap());
            assert_eq!(expected_merge[1], merged.end_exclusive.to_u64().unwrap());
        }
    }
}
