use crate::rng::{EspRandom, RngCallback};
use crate::ssl::{config::*, context::*};
use std::sync::Arc;

define!(
    #[c_ty(ssl_config)]
    #[repr(C)]
    struct Config {
        own_cert: Vec<Arc<Certificate>>,
        own_pk: Vec<Arc<Pk>>,
    };
    const drop: fn(&mut Self) = ssl_config_free;
    impl<'b> Into<ptr> {}
    impl<'b> UnsafeFrom<ptr> {}
);

unsafe impl Sync for Config {}

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

impl Config {
    pub fn new(e: Endpoint, t: Transport, p: Preset) -> Self {
        let mut inner = ssl_config::default();
        unsafe {
            ssl_config_init(&mut inner);
            ssl_config_defaults(&mut inner, e as c_int, t as c_int, p as c_int);
            ssl_conf_rng(&mut inner, Some(EspRandom::call), EspRandom.data_ptr());
        };

        Self {
            inner,
            own_cert: vec![],
            own_pk: vec![],
        }
    }

    pub fn push_cert(&mut self, own_cert: &Arc<Certificate>, own_pk: &Arc<Pk>) -> Result<()> {
        unsafe {
            ssl_conf_own_cert(
                self.into(),
                own_cert.inner_ffi_mut(),
                own_pk.inner_ffi_mut(),
            )
            .into_result_discard()?;
        }
        self.own_cert.push(Arc::clone(own_cert));
        self.own_pk.push(Arc::clone(own_pk));

        Ok(())
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
    #[repr(C)]
    struct Context {
        config: Arc<Config>,
    };
    const drop: fn(&mut Self) = ssl_free;
    impl<'b> Into<ptr> {}
    impl<'b> UnsafeFrom<ptr> {}
);

impl Context {
    pub fn new(config: &Arc<Config>) -> Result<Self> {
        let mut inner = ssl_context::default();
        let config = Arc::clone(&config);
        unsafe {
            ssl_init(&mut inner);
            ssl_setup(&mut inner, (&*config).into()).into_result()?;
        };

        Ok(Self { inner, config })
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
