pub trait CoverageTracker {
    fn name(&self) -> &'static str;
    fn record_block(&mut self, block: usize);

    fn print_result(&self);

    fn report_sizes(&self) -> (usize, usize);
}

mod fulltrace_32bit;
mod fulltrace_64bit;

mod xordiff_compressed_trace_uleb128;
mod less_trivial_dedup_fulltrace_32bit;

mod trivial_dedup_fulltrace_32bit;
mod trivial_dedup_fulltrace_64bit;

mod edge_hashset;
mod edge_btreeset;
mod block_btreeset;
mod block_hashset;


pub use fulltrace_32bit::FullTrace32Bit;
pub use fulltrace_64bit::FullTrace64Bit;
pub use trivial_dedup_fulltrace_32bit::TrivialDedupFullTrace32Bit;
pub use trivial_dedup_fulltrace_64bit::TrivialDedupFullTrace64Bit;
pub use less_trivial_dedup_fulltrace_32bit::LessTrivialDedupFullTrace32Bit;

pub use edge_hashset::EdgeHashSetCoverageInfo;
pub use edge_btreeset::EdgeBTreeSetCoverageInfo;
pub use block_hashset::BlockHashSetCoverageInfo;
pub use block_btreeset::BlockBTreeSetCoverageInfo;
pub use xordiff_compressed_trace_uleb128::XorDiffULeb128CompressedTrace;