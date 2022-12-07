use crate::rng::{RngCallback, RngCallbackMut};
use mbedtls_sys::sys::{esp_fill_random, esp_random};
use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};

pub struct EspRandom;

impl EspRandom {
    #[inline]
    pub fn fill_random(buf: &mut [u8]) {
        unsafe { esp_fill_random(buf.as_mut_ptr().cast(), buf.len() as _) }
    }

    #[inline]
    pub fn random() -> u32 {
        unsafe { esp_random() }
    }
}

impl RngCallback for EspRandom {
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: usize) -> c_int {
        esp_fill_random(data.cast(), len);
        0
    }

    fn data_ptr(&self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}

impl RngCallbackMut for EspRandom {
    unsafe extern "C" fn call_mut(_: *mut c_void, data: *mut c_uchar, len: usize) -> c_int {
        esp_fill_random(data.cast(), len);
        0
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}

impl rand_core::RngCore for EspRandom {
    fn next_u32(&mut self) -> u32 {
        Self::random()
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Self::fill_random(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Ok(Self::fill_random(dest))
    }
}
