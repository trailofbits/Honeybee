use std::collections::{BTreeSet};

use datasize::{DataSize, data_size};

use super::CoverageTracker;


#[derive(Debug, Eq, PartialEq, Clone, Default, DataSize)]
pub struct BlockBTreeSetCoverageInfo {
    hive_slide: usize,
    pub block_set: BTreeSet<usize>,
}

impl BlockBTreeSetCoverageInfo {
    pub fn new(hive_slide: usize) -> Self {
        Self {
            hive_slide,
            block_set: BTreeSet::new(),
        }
    }
}
impl CoverageTracker for BlockBTreeSetCoverageInfo {
    fn name(&self) -> &'static str {
        "BlockBTreeSetCoverageInfo"
    }
    fn record_block(&mut self, block: usize) {
        self.block_set.insert(block);
    }
    fn print_result(&self) {
        println!("Blocks: {} values = {} bytes", self.block_set.len(), data_size(&self.block_set));
    }
    fn report_sizes(&self) -> (usize, usize) {
        (self.block_set.len(), data_size(&self.block_set))
    }
}

