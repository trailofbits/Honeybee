use rust_honey_analyzer_sys::*;

// /** No error */
// HA_PT_DECODER_NO_ERROR = 0,
// /** The trace ended. This is not an error but rather an indication to stop */
// HA_PT_DECODER_END_OF_STREAM = 1,
// /** There was an internal decoder error. Probably not your fault. */
// HA_PT_DECODER_INTERNAL = 2,
// /** A sync operation failed because the target PSB could not be found. */
// HA_PT_DECODER_COULD_NOT_SYNC = 3,
// /**
//  * An operation was requested which could not be completed given the trace.
//  * This can mean one of three things:
//  * 1. The decoder is buggy
//  * 2. The analysis is buggy
//  * 3. The mapping between the binary and the decoder is incorrect (leading to bad analysis)
//  */
// HA_PT_DECODER_TRACE_DESYNC = 4,
// /** An unsupported packet was found in the PT stream. */
// HA_PT_DECODER_UNSUPPORTED_TRACE_PACKET = 5,
// /** The target address was not found in the binary map. */
// HA_PT_DECODER_NO_MAP = 6,

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PTDecoderStatus {
    NoError = ha_pt_decoder_status_HA_PT_DECODER_NO_ERROR as u32,
    EndOfStream = ha_pt_decoder_status_HA_PT_DECODER_END_OF_STREAM as u32,
    Internal = ha_pt_decoder_status_HA_PT_DECODER_INTERNAL as u32,
    CouldNotSync = ha_pt_decoder_status_HA_PT_DECODER_COULD_NOT_SYNC as u32,
    TraceDesync = ha_pt_decoder_status_HA_PT_DECODER_TRACE_DESYNC as u32,
    UnsupportedTracePacket = ha_pt_decoder_status_HA_PT_DECODER_UNSUPPORTED_TRACE_PACKET as u32,
    NoMap = ha_pt_decoder_status_HA_PT_DECODER_NO_MAP as u32,
}

impl TryFrom<i32> for PTDecoderStatus {
    type Error = String;

    fn try_from(value: i32) -> Result<PTDecoderStatus, String> {
        let res = match value as u32 {
            0 => Ok(PTDecoderStatus::NoError),
            1 => Ok(PTDecoderStatus::EndOfStream),
            2 => Ok(PTDecoderStatus::Internal),
            3 => Ok(PTDecoderStatus::CouldNotSync),
            4 => Ok(PTDecoderStatus::TraceDesync),
            5 => Ok(PTDecoderStatus::UnsupportedTracePacket),
            6 => Ok(PTDecoderStatus::NoMap),
            _ => Err(format!("Unknown PTDecoderStatus: {:?}", value))
        };
        if let Ok(val) = res {
            assert_eq!(val as i32, value);
        }
        res
    }
}