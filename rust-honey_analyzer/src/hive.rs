use std::ffi::CString;

use nix::errno::Errno;
use rust_honey_analyzer_sys::*;

pub struct HoneyBeeHive {
    hive: *mut hb_hive,
}

type ErrnoResult<T> = std::result::Result<T, Errno>;

impl Drop for HoneyBeeHive {
    fn drop(&mut self) {
        unsafe {
            hb_hive_free(self.hive)
        }
    }
}
impl HoneyBeeHive {
    pub fn load(path: &str) -> ErrnoResult<HoneyBeeHive> {
        let cstr = CString::new(path).unwrap();
        unsafe {
            let res  = hb_hive_alloc(cstr.as_ptr());
            assert!(!res.is_null(), "loading hive failed, error should have been printed to the console!");
            Ok(HoneyBeeHive{
                hive: res,
            })
        }
    }
    pub fn get_inner(&mut self) -> &mut hb_hive {
        unsafe { &mut *self.hive }
    }
    pub fn describe_block(&self, idx: usize) {
        unsafe {
            hb_hive_describe_block(self.hive, idx.try_into().unwrap());
        }
    }
    pub fn uvip_slide(&self) -> usize {
        unsafe {
            (*self.hive).uvip_slide.try_into().unwrap()
        }
    }
    pub fn block_count(&self) -> usize {
        unsafe {
            (*self.hive).block_count.try_into().unwrap()
        }
    }
}