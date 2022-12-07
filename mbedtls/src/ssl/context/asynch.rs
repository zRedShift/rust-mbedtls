use crate::rng::{EspRandom, RngCallback};
use crate::ssl::{config::*, context::*};
use async_io::Async;
use core::future::Future;
use core::pin::Pin;
use core::ptr::null_mut;
use core::slice::{from_raw_parts, from_raw_parts_mut};
use core::task::{Context as TaskContext, Poll};
use futures_lite::{
    io::{AsyncRead, AsyncWrite},
    ready,
};
use std::net::TcpStream;
use ErrorKind::*;

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
    struct HandshakeContext<'a>;
    const init: fn() -> Self = ssl_init;
    const drop: fn(&mut Self) = ssl_free;
    impl<'b> Into<ptr> {}
    impl<'b> UnsafeFrom<ptr> {}
);

impl<'a> HandshakeContext<'a> {
    fn new(config: &'a Config<'a>) -> Result<Self> {
        let mut context = Self::init();
        unsafe { ssl_setup(context.handle_mut(), config.handle()) }.into_result()?;
        Ok(context)
    }
}

pub struct Context<'a> {
    inner: HandshakeContext<'a>,
    io: Pin<&'a mut Async<TcpStream>>,
    ssl_closed: bool,
}

unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: usize) -> c_int {
    let len = len.min(c_int::MAX as usize);
    match (&mut *(user_data as *mut Async<TcpStream>))
        .get_mut()
        .read(from_raw_parts_mut(data, len as _))
        .map_err(|err| err.kind())
    {
        Ok(i) => i as c_int,
        Err(WouldBlock | Interrupted | TimedOut) => ERR_SSL_WANT_READ,
        Err(BrokenPipe | ConnectionReset) => ERR_NET_CONN_RESET,
        _ => ERR_NET_RECV_FAILED,
    }
}

unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: usize) -> c_int {
    let len = len.min(c_int::MAX as usize);
    match (&mut *(user_data as *mut Async<TcpStream>))
        .get_mut()
        .write(from_raw_parts(data, len as _))
        .map_err(|err| err.kind())
    {
        Ok(i) => i as c_int,
        Err(WouldBlock | Interrupted | TimedOut) => ERR_SSL_WANT_WRITE,
        Err(BrokenPipe | ConnectionReset) => ERR_NET_CONN_RESET,
        _ => ERR_NET_SEND_FAILED,
    }
}

fn io_res_to_res_read<T>(res: IoResult<T>) -> Result<T> {
    res.map_err(|err| match err.kind() {
        WouldBlock | Interrupted | TimedOut => Error::SslWantRead,
        BrokenPipe | ConnectionReset => Error::NetConnReset,
        _ => Error::NetRecvFailed,
    })
}

fn io_res_to_res_write<T>(res: IoResult<T>) -> Result<T> {
    res.map_err(|err| match err.kind() {
        WouldBlock | Interrupted | TimedOut => Error::SslWantWrite,
        BrokenPipe | ConnectionReset => Error::NetConnReset,
        _ => Error::NetSendFailed,
    })
}

impl<'a> Context<'a> {
    pub fn new(config: &'a Config<'a>, mut io: Pin<&'a mut Async<TcpStream>>) -> Result<Self> {
        let mut inner = HandshakeContext::new(config)?;
        let ptr = &mut *io as *mut _ as *mut c_void;
        unsafe {
            ssl_set_bio(
                inner.handle_mut(),
                ptr,
                Some(call_send),
                Some(call_recv),
                None,
            );
        }
        Ok(Self {
            inner,
            io,
            ssl_closed: false,
        })
    }

    // fn handshake_inner(&mut self) -> Result<()> {
    //     unsafe { ssl_handshake(self.inner.handle_mut()) }.into_result_discard()
    // }

    fn read_inner(&mut self, buf: &mut [u8]) -> Result<c_int> {
        unsafe { ssl_read(self.inner.handle_mut(), buf.as_mut_ptr(), buf.len() as _) }.into_result()
    }

    fn write_inner(&mut self, buf: &[u8]) -> Result<c_int> {
        unsafe { ssl_write(self.inner.handle_mut(), buf.as_ptr(), buf.len() as _) }.into_result()
    }

    fn io_inner(
        &mut self,
        cx: &mut TaskContext<'_>,
        res: Result<c_int>,
    ) -> Poll<IoResult<Option<usize>>> {
        match res {
            Ok(i) => Poll::Ready(Ok(Some(i as usize))),
            Err(Error::SslPeerCloseNotify) => Poll::Ready(Ok(Some(0))),
            Err(Error::SslWantRead) => self.io.poll_readable(cx).map(|res| res.map(|_| None)),
            Err(Error::SslWantWrite) => self.io.poll_writable(cx).map(|res| res.map(|_| None)),
            Err(err) => Poll::Ready(Err(IoError::new(Other, err))),
        }
    }

    async fn io_inner_async<F: FnMut(&mut Self) -> Result<c_int>>(
        &mut self,
        mut io: F,
    ) -> Result<usize> {
        loop {
            match io(self) {
                Ok(i) => return Ok(i as usize),
                Err(Error::SslPeerCloseNotify) => return Ok(0),
                Err(Error::SslWantRead) => io_res_to_res_read(self.io.readable().await)?,
                Err(Error::SslWantWrite) => io_res_to_res_write(self.io.writable().await)?,
                Err(err) => return Err(err),
            }
        }
    }

    pub async fn close(&mut self) -> Result<()> {
        if !self.ssl_closed {
            self.io_inner_async(Self::close_inner).await?;
            self.ssl_closed = true;
            unsafe { ssl_set_bio((*self).inner.handle_mut(), null_mut(), None, None, None) };
        }
        Ok(())
    }

    fn close_inner(&mut self) -> Result<c_int> {
        unsafe { ssl_close_notify(self.inner.handle_mut()) }.into_result()
    }
}

impl<'a> AsyncRead for Context<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        loop {
            let res = (*self).read_inner(buf);
            if let Some(i) = ready!((*self).io_inner(cx, res))? {
                return Poll::Ready(Ok(i));
            }
        }
    }
}

impl<'a> AsyncWrite for Context<'a> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<IoResult<usize>> {
        if (*self).ssl_closed {
            return Pin::new(&mut (*self.io))
                .poll_close(cx)
                .map(|res| res.map(|_| 0));
        }
        loop {
            let res = (*self).write_inner(buf);
            if let Some(i) = ready!((*self).io_inner(cx, res))? {
                return Poll::Ready(Ok(i));
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        Pin::new(&mut (*self.io)).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<IoResult<()>> {
        while !(*self).ssl_closed {
            let res = (*self).close_inner();
            if let Some(_) = ready!((*self).io_inner(cx, res))? {
                (*self).ssl_closed = true;
                unsafe { ssl_set_bio((*self).inner.handle_mut(), null_mut(), None, None, None) };
            }
        }
        Pin::new(&mut *(self.io)).poll_close(cx)
    }
}

use embedded_io::{
    asynch::{Read as EmbIoRead, Write as EmbIoWrite},
    Error as EmbIoError, ErrorKind as EmbIoErrorKind, Io,
};

impl EmbIoError for Error {
    fn kind(&self) -> EmbIoErrorKind {
        EmbIoErrorKind::Other
    }
}

impl<'a> Io for Context<'a> {
    type Error = Error;
}

impl<'a> EmbIoRead for Context<'a> {
    type ReadFuture<'b> = impl Future<Output = Result<usize>> + 'b where 'a: 'b;

    fn read<'b>(&'b mut self, buf: &'b mut [u8]) -> Self::ReadFuture<'b> {
        self.io_inner_async(move |ctx| ctx.read_inner(buf))
    }
}

impl<'a> EmbIoWrite for Context<'a> {
    type WriteFuture<'b> = impl Future<Output = Result<usize>> + 'b where 'a: 'b;

    fn write<'b>(&'b mut self, buf: &'b [u8]) -> Self::WriteFuture<'b> {
        async move {
            if self.ssl_closed {
                return Ok(0);
            }
            self.io_inner_async(move |ctx| ctx.write_inner(buf)).await
        }
    }

    type FlushFuture<'b> = impl Future<Output = Result<()>> + 'b where 'a: 'b;

    fn flush<'b>(&'b mut self) -> Self::FlushFuture<'b> {
        async { Ok(()) }
    }
}
