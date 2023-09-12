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

const MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80: u16 = 0x0001;
const MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32: u16 = 0x0002;
const MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80: u16 = 0x0005;
const MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32: u16 = 0x0006;
const MBEDTLS_TLS_SRTP_UNSET: u16 = 0x0000;

const DEFAULT_SRTP_PROFILES: [ssl_srtp_profile; 5] = [
    MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80,
    MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32,
    MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80,
    MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32,
    MBEDTLS_TLS_SRTP_UNSET,
];

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

    /// Required for SRTP negotiation
    pub fn set_default_srtp_profiles(&mut self) -> Result<()> {
        unsafe {
            ssl_conf_dtls_srtp_protection_profiles(self.into(), DEFAULT_SRTP_PROFILES.as_ptr())
                .into_result_discard()
        }
    }

    pub fn set_ciphersuites(&mut self, ciphersuites: &[i32]) -> Result<()> {
        unsafe { ssl_conf_ciphersuites(self.into(), ciphersuites.as_ptr()) }
        Ok(())
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

    pub fn handshake(&mut self) -> Result<c_int> {
        unsafe { ssl_handshake(self.handle_mut()) }.into_result()
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

    pub unsafe fn set_key_export_cb(&mut self, cb: ssl_export_keys_t, keys: *mut c_void) {
        ssl_set_export_keys_cb(self.handle_mut(), cb, keys)
    }

    pub unsafe fn get_dtls_srtp_negotiation_result(&self, info: *mut dtls_srtp_info) {
        ssl_get_dtls_srtp_negotiation_result(self.handle(), info)
    }
}

impl embedded_io::Error for Error {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}
