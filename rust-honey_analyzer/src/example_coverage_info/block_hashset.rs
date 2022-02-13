use std::collections::HashSet;

use datasize::{DataSize, data_size};

use super::CoverageTracker;


#[derive(Debug, Eq, PartialEq, Clone, Default, DataSize)]
pub struct BlockHashSetCoverageInfo {
    hive_slide: usize,
    pub block_set: HashSet<usize>,
}

impl BlockHashSetCoverageInfo {
    pub fn new(hive_slide: usize) -> Self {
        Self {
            hive_slide,
            block_set: HashSet::with_capacity(100),
        }
    }
}
impl CoverageTracker for BlockHashSetCoverageInfo {
    fn name(&self) -> &'static str {
        "BlockHashSetCoverageInfo"
    }
    fn record_block(&mut self, block: usize) {
        self.block_set.insert(block);
    }
    fn print_result(&self) {
        println!("Basic blocks: {} values = {} bytes", self.block_set.len(), data_size(&self.block_set));
    }
    fn report_sizes(&self) -> (usize, usize) {
        (self.block_set.len(), data_size(&self.block_set))
    }
}

