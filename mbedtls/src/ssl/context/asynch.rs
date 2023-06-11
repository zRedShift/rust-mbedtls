use crate::rng::{EspRandom, RngCallback};
use crate::ssl::{config::*, context::*};

define!(
    #[c_ty(ssl_config)]
    #[repr(transparent)]
    struct Config<'a>;
    const init: fn() -> Self = ssl_config_init;
    const drop: fn(&mut Self) = ssl_config_free;
    impl<'b> Into<ptr> {}
    impl<'b> UnsafeFrom<ptr> {}
);

unsafe impl<'a> Sync for Config<'a> {}

impl<'a> Config<'a> {
    pub fn new(e: Endpoint, t: Transport, p: Preset) -> Self {
        let mut config = Self::init();
        let conf = config.handle_mut();
        unsafe {
            ssl_config_defaults(conf, e as c_int, t as c_int, p as c_int);
            ssl_conf_rng(conf, Some(EspRandom::call), EspRandom.data_ptr());
        };
        config
    }

    pub fn push_cert(&mut self, own_cert: &'a Certificate, own_pk: &'a Pk) -> Result<()> {
        unsafe {
            ssl_conf_own_cert(
                self.into(),
                own_cert.inner_ffi_mut(),
                own_pk.inner_ffi_mut(),
            )
            .into_result_discard()
        }
    }

    setter!(set_authmode(am: AuthMode) = ssl_conf_authmode);
}

define!(
    #[c_ty(ssl_context)]
    #[repr(transparent)]
    struct Context<'a>;
    const init: fn() -> Self = ssl_init;
    const drop: fn(&mut Self) = ssl_free;
    impl<'b> Into<ptr> {}
    impl<'b> UnsafeFrom<ptr> {}
);

impl<'a> Context<'a> {
    pub fn new(config: &'a Config<'a>) -> Result<Self> {
        let mut context = Self::init();
        unsafe { ssl_setup(context.handle_mut(), config.handle()) }.into_result()?;
        Ok(context)
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<c_int> {
        unsafe { ssl_read(self.handle_mut(), buf.as_mut_ptr(), buf.len() as _) }.into_result()
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<c_int> {
        unsafe { ssl_write(self.handle_mut(), buf.as_ptr(), buf.len() as _) }.into_result()
    }

    pub fn close(&mut self) -> Result<c_int> {
        unsafe { ssl_close_notify(self.handle_mut()) }.into_result()
    }

    /// # Safety
    /// TODO
    pub unsafe fn set_bio(
        &mut self,
        arg: *mut c_void,
        send: ssl_send_t,
        recv: ssl_recv_t,
        timeout: ssl_recv_timeout_t,
    ) {
        ssl_set_bio(self.handle_mut(), arg, send, recv, timeout)
    }

    /// # Safety
    /// TODO
    pub unsafe fn set_timer_cb(
        &mut self,
        timer: *mut c_void,
        set: ssl_set_timer_t,
        get: ssl_get_timer_t,
    ) {
        ssl_set_timer_cb(self.handle_mut(), timer, set, get)
    }
}

impl embedded_io::Error for Error {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}
