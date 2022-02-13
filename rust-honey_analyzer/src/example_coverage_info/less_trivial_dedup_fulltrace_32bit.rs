use std::mem::size_of;

use datasize::{DataSize, data_size};

use super::CoverageTracker;


#[derive(Debug, Eq, PartialEq, Clone, Default, DataSize)]
pub struct LessTrivialDedupFullTrace32Bit {
    hive_slide: usize,
    prevprev: usize,
    prev: usize,
    pub bbs: Vec<u32>,
}

impl LessTrivialDedupFullTrace32Bit {
    pub fn new(hive_slide: usize, ) -> Self {
        let vec = Vec::with_capacity(1000);
        Self {
            hive_slide,
            prevprev : 0,
            prev : 0,
            bbs: vec,
        }
    }
}
impl CoverageTracker for LessTrivialDedupFullTrace32Bit {
    fn name(&self) -> &'static str {
        "LessTrivialDedupFullTrace32Bit"
    }
    fn record_block(&mut self, block: usize) {
        let (prev, prevprev) = (self.prev, self.prevprev);
        (self.prev, self.prevprev) = (block, prev);
        if block == prev && block == prevprev {
            return;
        }
        self.bbs.push((block - self.hive_slide).try_into().unwrap());
    }
    fn print_result(&self) {
        let l = self.bbs.len();
        println!("Trace length: {} values = {} bytes", l, 4 * l);
    }
    fn report_sizes(&self) -> (usize, usize) {
        (self.bbs.len(), data_size(&self.bbs))
    }
}

