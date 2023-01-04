use crate::error::{Error, IntoResult, Result};
use mbedtls_sys::*;

define!(
    #[c_ty(sha1_context)]
    struct Sha1;
    const init: fn() -> Self = sha1_init;
    const drop: fn(&mut Self) = sha1_free;
    impl<'a> Into<ptr> {}
);

const SHA1_DIGEST_LEN: usize = 20;

impl Sha1 {
    pub fn new() -> Result<Self> {
        let mut ctx = Self::init();
        ctx.reset()?;
        Ok(ctx)
    }

    pub fn reset(&mut self) -> Result<()> {
        unsafe { sha1_starts(&mut self.inner) }.into_result_discard()
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        unsafe { sha1_update(&mut self.inner, data.as_ptr(), data.len() as _) }
            .into_result_discard()
    }

    pub fn finish_into(&mut self, out: &mut [u8]) -> Result<()> {
        if out.len() < SHA1_DIGEST_LEN {
            return Err(Error::MdBadInputData);
        }
        unsafe { sha1_finish(&mut self.inner, out.as_mut_ptr()) }.into_result()?;
        self.reset()
    }

    pub fn finish(&mut self) -> Result<[u8; SHA1_DIGEST_LEN]> {
        let mut digest = [0u8; 20];
        self.finish_into(&mut digest)?;
        Ok(digest)
    }
}
