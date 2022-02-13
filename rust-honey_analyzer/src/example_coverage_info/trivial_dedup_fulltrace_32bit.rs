use datasize::{DataSize, data_size};

use super::CoverageTracker;


#[derive(Debug, Eq, PartialEq, Clone, Default, DataSize)]
pub struct TrivialDedupFullTrace32Bit {
    hive_slide: usize,
    last_block: usize,
    pub bbs: Vec<u32>,
}

impl TrivialDedupFullTrace32Bit {
    pub fn new(hive_slide: usize, ) -> Self {
        let vec = Vec::with_capacity(1000);
        Self {
            hive_slide,
            last_block : 0,
            bbs: vec,
        }
    }
}
impl CoverageTracker for TrivialDedupFullTrace32Bit {
    fn name(&self) -> &'static str {
        "TrivialDedupFullTrace32Bit"
    }
    fn record_block(&mut self, block: usize) {
        let last = self.last_block;
        self.last_block = block;
        if last == block {
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

