use datasize::{DataSize, data_size};
use itertools::Itertools;

use super::CoverageTracker;


#[derive(Debug, Eq, PartialEq, Clone, Default, DataSize)]
pub struct FullTrace64Bit {
    hive_slide: usize,
    pub bbs: Vec<usize>,
}

impl FullTrace64Bit {
    pub fn new(hive_slide: usize) -> FullTrace64Bit {
        let vec = Vec::with_capacity(1000);
        FullTrace64Bit {
            hive_slide,
            bbs: vec,
        }
    }
}
impl CoverageTracker for FullTrace64Bit {
    fn name(&self) -> &'static str {
        "FullTrace64Bit"
    }
    fn record_block(&mut self, block: usize) {
        self.bbs.push(block);
    }
    fn print_result(&self) {
        let l = self.bbs.len();
        println!("Trace length: {} values = {} bytes", l, 8 * l);
    }
    fn report_sizes(&self) -> (usize, usize) {
        let uniq_edges = self.bbs[0..(self.bbs.len()-1)].iter().zip(self.bbs[1..].iter()).unique().collect::<Vec<_>>();
        // (self.bbs.len(), data_size(&self.bbs))
        (uniq_edges.len(), data_size(&self.bbs))
    }
}

