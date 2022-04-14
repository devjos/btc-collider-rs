use super::SearchSpace;
use super::SearchSpaceProvider;
use log::{debug, info};
use num_bigint::{BigUint, RandBigInt};
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufWriter, Write};
use std::ops::Add;

pub struct FileSearchSpaceProvider {
    done: BTreeSet<SearchSpace>,
    pending: BTreeSet<SearchSpace>,
    interval: BigUint,
    file: String,
}

impl FileSearchSpaceProvider {
    pub fn new(file: &'static str) -> FileSearchSpaceProvider {
        let mut done = BTreeSet::new();

        match File::open(&file) {
            Ok(f) => {
                for line in io::BufReader::new(f).lines() {
                    let search_space = SearchSpace::from_line(&line.unwrap());
                    done.insert(search_space);
                }
            }
            Err(_) => info!("No existing search space file found."),
        }

        let interval: u64 = 1_000_000;
        FileSearchSpaceProvider {
            done,
            pending: BTreeSet::new(),
            interval: BigUint::from(interval),
            file: file.to_string(),
        }
    }

    fn add(&mut self, search_space: &SearchSpace) {
        let mut merge_lower = false;
        let mut merge_higher = false;

        let mut lower_search_space = Option::None;
        for s in self.done.iter() {
            if s.cmp(&search_space).is_lt() {
                lower_search_space = Option::Some(s.clone());
            }
        }

        if lower_search_space.is_some()
            && lower_search_space.clone().unwrap().can_merge(&search_space)
        {
            self.done.remove(&lower_search_space.clone().unwrap());
            merge_lower = true;
        }

        let mut higher_search_space = Option::None;
        for s in self.done.iter() {
            if s.cmp(&search_space).is_gt() {
                higher_search_space = Option::Some(s.clone());
                break;
            }
        }

        if higher_search_space.is_some()
            && higher_search_space
                .clone()
                .unwrap()
                .can_merge(&search_space)
        {
            self.done.remove(&higher_search_space.clone().unwrap());
            merge_higher = true;
        }

        if merge_lower && merge_higher {
            let merged = SearchSpace {
                start_inclusive: lower_search_space.unwrap().start_inclusive.clone(),
                end_exclusive: higher_search_space.unwrap().end_exclusive.clone(),
            };
            self.done.insert(merged);
        } else if merge_lower {
            let merged = lower_search_space.unwrap().merge(search_space);
            self.done.insert(merged);
        } else if merge_higher {
            let merged = higher_search_space.unwrap().merge(search_space);
            self.done.insert(merged);
        } else {
            self.done.insert(search_space.clone());
        }
    }
}

impl SearchSpaceProvider for FileSearchSpaceProvider {
    fn next(&mut self) -> SearchSpace {
        let start_inclusive;

        if !self.pending.is_empty() {
            let last = self.pending.last().unwrap();
            start_inclusive = last.end_exclusive.clone();
        } else if !self.done.is_empty() {
            let first = self.done.first().unwrap();
            start_inclusive = first.end_exclusive.clone();
        } else {
            let mut rng = rand::thread_rng();
            start_inclusive = rng.gen_biguint(256);
        }

        let search_space = SearchSpace {
            start_inclusive: start_inclusive.clone(),
            end_exclusive: start_inclusive.clone().add(&self.interval),
        };
        self.pending.insert(search_space.clone());
        debug!("Created next search space {}", search_space);
        search_space
    }

    fn done(&mut self, search_space: &SearchSpace) {
        if !self.pending.remove(&search_space) {
            panic!("Could not remove from pending");
        }

        self.add(&search_space);

        let f = File::create(&self.file).unwrap();
        let mut f = BufWriter::new(f);
        for search_space in &self.done {
            f.write(format!("{}\n", search_space).as_bytes()).unwrap();
        }
        f.flush().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::search_space::file_search_space_provider::FileSearchSpaceProvider;
    use crate::SearchSpaceProvider;
    use num_traits::ToPrimitive;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn can_read_from_file() {
        let mut prov = FileSearchSpaceProvider::new("searchspace/space.existing.txt");

        let search_space = prov.next();
        assert_eq!(10, search_space.start_inclusive.to_u64().unwrap());
        assert_eq!(1_000_010, search_space.end_exclusive.to_u64().unwrap());
    }

    #[test]
    fn can_update() {
        let file = "searchspace/space.update.txt";

        let mut f = File::create(&file).unwrap();
        f.write("4-b".as_bytes()).unwrap();

        let mut prov = FileSearchSpaceProvider::new(&file);
        let search_space = prov.next();
        assert_eq!("b-f424b", search_space.to_string());

        prov.done(&search_space);

        let file_content = std::fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = file_content.lines().collect();
        assert_eq!(1, lines.len());
        assert_eq!("4-f424b", *lines.get(0).unwrap());
    }

    #[test]
    fn can_correctly_merge() {
        let file = "searchspace/space.merge.txt";
        std::fs::write(&file, "4-b").unwrap();

        let mut p = FileSearchSpaceProvider::new(file);
        let s1 = p.next();
        assert_eq!("b-f424b", s1.to_string());

        let s2 = p.next();
        assert_eq!("f424b-1e848b", s2.to_string());

        p.done(&s2);
        let file_content = std::fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = file_content.lines().collect();
        assert_eq!(2, lines.len());
        assert_eq!("4-b", *lines.get(0).unwrap());
        assert_eq!("f424b-1e848b", *lines.get(1).unwrap());

        p.done(&s1);
        let file_content = std::fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = file_content.lines().collect();
        assert_eq!(1, lines.len());
        assert_eq!("4-1e848b", *lines.get(0).unwrap());
    }
}
