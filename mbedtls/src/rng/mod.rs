/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

pub mod ctr_drbg;
mod esp_random;
pub mod hmac_drbg;
#[cfg(sys_std_component = "entropy")]
pub mod os_entropy;
#[cfg(any(feature = "rdrand", target_env = "sgx"))]
mod rdrand;

#[doc(inline)]
pub use self::ctr_drbg::CtrDrbg;
#[doc(inline)]
pub use self::hmac_drbg::HmacDrbg;
#[cfg(sys_std_component = "entropy")]
#[doc(inline)]
pub use self::os_entropy::OsEntropy;
#[cfg(any(feature = "rdrand", target_env = "sgx"))]
pub use self::rdrand::{Entropy as Rdseed, Nrbg as Rdrand};
pub use esp_random::EspRandom;

use crate::error::{IntoResult, Result};
use mbedtls_sys::types::raw_types::{c_int, c_uchar};

callback!(EntropyCallbackMut,EntropyCallback(data: *mut c_uchar, len: usize) -> c_int);
callback!(RngCallbackMut,RngCallback(data: *mut c_uchar, len: usize) -> c_int);

pub trait Random: RngCallback {
    fn random(&mut self, data: &mut [u8]) -> Result<()>
    where
        Self: Sized,
    {
        unsafe { Self::call(self.data_ptr(), data.as_mut_ptr(), data.len() as _) }.into_result()?;
        Ok(())
    }
}

impl<'r, F: RngCallback> Random for F {}
