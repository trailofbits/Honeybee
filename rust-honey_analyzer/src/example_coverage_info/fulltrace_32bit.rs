use datasize::{DataSize, data_size};

use super::CoverageTracker;


#[derive(Debug, Eq, PartialEq, Clone, Default, DataSize)]
pub struct FullTrace32Bit {
    hive_slide: usize,
    pub bbs: Vec<u32>,
}

impl FullTrace32Bit {
    pub fn new(hive_slide: usize, ) -> Self {
        let vec = Vec::with_capacity(1000);
        Self {
            hive_slide,
            bbs: vec,
        }
    }
}
impl CoverageTracker for FullTrace32Bit {
    fn name(&self) -> &'static str {
        "FullTrace32Bit"
    }
    fn record_block(&mut self, block: usize) {
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

