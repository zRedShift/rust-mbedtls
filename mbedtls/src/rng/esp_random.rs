use mbedtls_sys::sys::esp_fill_random;
use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;

use crate::rng::{RngCallback, RngCallbackMut};

pub struct EspRandom;

impl RngCallback for EspRandom {
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        esp_fill_random(data.cast(), len);
        0
    }

    fn data_ptr(&self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}

impl RngCallbackMut for EspRandom {
    unsafe extern "C" fn call_mut(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        esp_fill_random(data.cast(), len);
        0
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        ::core::ptr::null_mut()
    }
}
