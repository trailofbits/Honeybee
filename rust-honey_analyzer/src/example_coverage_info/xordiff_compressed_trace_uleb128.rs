use datasize::{DataSize, data_size};
use uleb128::WriteULeb128Ext;

use super::CoverageTracker;


#[derive(Debug, Eq, PartialEq, Clone, Default, DataSize)]
pub struct XorDiffULeb128CompressedTrace {
    hive_slide: usize,
    last_block: usize,
    num_vals: usize,
    compressed_trace: Vec<u8>,
}

impl XorDiffULeb128CompressedTrace {
    pub fn new(hive_slide: usize) -> XorDiffULeb128CompressedTrace {
        let vec = Vec::with_capacity(1000);
        XorDiffULeb128CompressedTrace {
            hive_slide,
            last_block: 0,
            num_vals: 0,
            compressed_trace: vec,
        }
    }
}
impl CoverageTracker for XorDiffULeb128CompressedTrace {
    fn name(&self) -> &'static str {
        "CompressedTraceXorDiffULeb128"
    }
    fn record_block(&mut self, block: usize) {
        let last = self.last_block;
        self.last_block = block;

        if last == block {
            return;
        }

        let xordiff = block ^ last;
        self.num_vals += 1;
        // println!("0x{:x} ^ 0x{:x} = 0x{:x}", block, last, block ^ last);

        let mut wtr = vec![];
        wtr.write_uleb128_u32(xordiff.try_into().unwrap()).unwrap();
        self.compressed_trace.append(&mut wtr);
        self.last_block = block;
    }
    fn print_result(&self) {
        println!("Compressed length: {} values = {} bytes", self.num_vals, self.compressed_trace.len());
    }
    fn report_sizes(&self) -> (usize, usize) {
        (self.num_vals, data_size(&self.compressed_trace))
    }
}

