use std::ptr;

use libc::c_void;
use nix::errno::Errno;
use rust_honey_analyzer_sys::*;

use crate::pt_decoder_status::PTDecoderStatus;

use super::hive::HoneyBeeHive;

extern "C" fn coverage_trampoline<F>(_: ha_session_t, context: *mut c_void, unslid_ip: u64)
    where F: FnMut(u64)
{
    unsafe {
        let cb = &mut *(context as *mut F);
        (cb)(unslid_ip)
    }
}

pub struct AnalysisSession {
    sess: ha_session_t,
    _hive: HoneyBeeHive,
    current_buffer: Vec<u8>
}

type ErrnoResult<T> = std::result::Result<T, Errno>;

impl Drop for AnalysisSession {
    fn drop(&mut self) {
        unsafe {
            ha_session_free(self.sess)
        }
    }
}
impl AnalysisSession {
    pub fn new(hive: HoneyBeeHive) -> ErrnoResult<AnalysisSession> {
        let mut sess = ptr::null_mut();
        let mut hive = hive;
        unsafe {
            let res  = ha_session_alloc(&mut sess, hive.get_inner());
            if res < 0 {
                return Err(Errno::from_i32(-res));
            }
            return Ok(AnalysisSession{
                sess,
                _hive: hive,
                current_buffer: vec![]
            })
        }
    }


    pub fn decode_with_callback<F>(&mut self, callback: F) -> Result<(), PTDecoderStatus>
        where F: FnMut(u64)
    {
        let mut callback = callback;
        unsafe {
            let context = &mut callback as *mut F as *mut c_void;

            let res = ha_session_decode(self.sess, Some(coverage_trampoline::<F>), context);
            assert!(res < 0, "ha_session_decode should always return -EOF on success!");
            let res: PTDecoderStatus = (-res).try_into().unwrap();
            match res {
                PTDecoderStatus::EndOfStream => Ok(()),
                _ => Err(res)
            }
        }
    }

    pub fn reconfigure_with_terminated_trace_buffer(&mut self, buf: Vec<u8>, trace_slide: usize) -> ErrnoResult<()> {
        self.current_buffer = buf;
        unsafe {
            let res = ha_session_reconfigure_with_terminated_trace_buffer(
                self.sess,
                self.current_buffer.as_mut_ptr(),
                self.current_buffer.len().try_into().unwrap(),
                trace_slide.try_into().unwrap());
            if res < 0 {
                return Err(Errno::from_i32(-res))
            }
            Ok(())
        }
    }

}