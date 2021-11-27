use super::SearchSpace;
use super::SearchSpaceProvider;

pub struct FileSearchSpaceProvider {
    file: String,
}

pub struct RandomSearchSpaceProvider {}

impl FileSearchSpaceProvider {
    pub fn new(file: &'static str) -> FileSearchSpaceProvider {
        FileSearchSpaceProvider {
            file: file.to_string(),
        }
    }
}

impl SearchSpaceProvider for FileSearchSpaceProvider {
    fn next(&self) -> SearchSpace {
        todo!()
    }

    fn done(&mut self, search_space: &SearchSpace) {
        todo!()
    }
}
