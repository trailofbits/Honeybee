use std::{ptr};

use nix::{unistd::Pid, errno::Errno, sched::CpuSet};
use rust_honey_analyzer_sys::*;
use crate::capture_filter::CaptureFilter;

#[derive(Debug)]
pub struct CaptureSession {
    sess: ha_capture_session_t,
    cpu_id: u16
}

type ErrnoResult<T> = std::result::Result<T, (String, Errno)>;

impl Drop for CaptureSession {
    fn drop(&mut self) {
        unsafe {
            ha_capture_session_free(self.sess)
        }
    }
}
fn errno_err<T>(reason: &str, errno: i32) -> ErrnoResult<T> {
    Err((String::from(reason), Errno::from_i32(errno)))
}
impl CaptureSession {
    pub fn new(cpu_id: u16) -> ErrnoResult<CaptureSession> {
        let mut x : ha_capture_session_t = ptr::null_mut();
        unsafe {
            println!("Calling ha_capture_session_alloc");
            let res  = ha_capture_session_alloc(&mut x, cpu_id);
            if res < 0 {
                return errno_err("ha_capture_session_alloc", -res);
            }
            return Ok(CaptureSession{
                sess: x,
                cpu_id
            })
        }
    }
    pub fn set_global_buffer_size(&mut self, buffer_count: u32, page_power: u8) -> ErrnoResult<()> {
        unsafe {
            let res = ha_capture_session_set_global_buffer_size(self.sess, buffer_count, page_power);
            if res < 0 {
                return errno_err("ha_capture_session_set_global_buffer_size", -res);
            }
            Ok(())
        }
    }
    pub fn set_trace_enable(&mut self, enabled: bool, reset_output: bool) -> ErrnoResult<()> {
        unsafe {
            let res = ha_capture_session_set_trace_enable(self.sess, enabled as u8, reset_output as u8);
            if res < 0 {
                return errno_err("ha_capture_session_set_trace_enable", -res);
            }
            Ok(())
        }
    }
    pub fn configure_tracing(&mut self, pid: u32, filters: &[CaptureFilter]) -> ErrnoResult<()> {
        if filters.len() > 4{
            return Err((String::from("too many filters"), Errno::EINVAL))
        }
        // Ensure `pid` is bound (`sched_set_affinity`) to this session's CPU for accurate results!
        let cpu_set = nix::sched::sched_getaffinity(Pid::from_raw(pid.try_into().unwrap())).expect("Cannot set process affinity");
        let valid_cpus = (0..CpuSet::count())
            .filter_map(|i| -> Option<Result<u16, (String, Errno)>> {
                    match cpu_set.is_set(i) {
                        Ok(true) => Some(Ok(i.try_into().unwrap())),
                        Ok(false) => None,
                        Err(e) => Some(Err((String::from("cpu_set.is_set"), e)))
                    }
                }
            )
            .collect::<Result<Vec<_>, _>>()?;

        assert!(valid_cpus.len() == 1,
            "Pid {} is not bound to a single CPU, getting an accurate trace for it will be impossible! It can run on CPUs {:?}",
            pid, valid_cpus
        );
        assert!(valid_cpus[0] == self.cpu_id, "Pid {} is not bound to this session's CPU #{}.", pid, self.cpu_id);

        unsafe {
            let res = ha_capture_session_configure_tracing(self.sess, pid, filters.as_ptr());
            if res < 0 {
                return errno_err("ha_capture_session_configure_tracing", -res);
            }
            Ok(())
        }
    }
    pub fn get_trace(&self) -> ErrnoResult<Vec<u8>> {
        let mut trace_buffer: *mut u8 = std::ptr::null_mut();
        let mut trace_length: u64 = 0;
        unsafe {
            let res = ha_capture_session_get_trace(self.sess, &mut trace_buffer, &mut trace_length);
            if res < 0 {
                return errno_err("ha_capture_session_get_trace", -res);
            }
            assert!(!trace_buffer.is_null());
            let slice = std::slice::from_raw_parts_mut(trace_buffer, trace_length as usize + 1);
            Ok(slice.to_vec())
        }
    }
}