use std::collections::BTreeSet;

use datasize::{DataSize, data_size};

use super::CoverageTracker;


#[derive(Debug, Eq, PartialEq, Clone, Default, DataSize)]
pub struct EdgeBTreeSetCoverageInfo {
    hive_slide: usize,
    last_block: usize,
    pub edge_set: BTreeSet<(usize, usize)>,
}

impl EdgeBTreeSetCoverageInfo {
    pub fn new(hive_slide: usize) -> Self {
        Self {
            hive_slide,
            last_block: 0,
            edge_set: BTreeSet::new(),
        }
    }
}
impl CoverageTracker for EdgeBTreeSetCoverageInfo {
    fn name(&self) -> &'static str {
        "EdgeBTreeSetCoverageInfo"
    }
    fn record_block(&mut self, block: usize) {
        let last = self.last_block;
        self.last_block = block;

        self.edge_set.insert((last, block));
    }
    fn print_result(&self) {
        println!("Edges:        {} values = {} bytes", self.edge_set.len(),  data_size(&self.edge_set));
    }
    fn report_sizes(&self) -> (usize, usize) {
        (self.edge_set.len(), data_size(&self.edge_set))
    }
}

