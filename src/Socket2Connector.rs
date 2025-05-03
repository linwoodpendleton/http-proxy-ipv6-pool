use hyper::client::connect::{Connected, Connection};
use hyper::service::Service;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd};

// 自定义 Socket2Connector
#[derive(Clone)]
pub struct Socket2Connector<C> {
    inner: C,
    interface: Option<String>,
}

impl<C> Socket2Connector<C> {
    pub fn new(inner: C, interface: Option<&str>) -> Self {
        Self {
            inner,
            interface: interface.map(String::from),
        }
    }
}

impl<C> Service<hyper::Uri> for Socket2Connector<C>
where
    C: Service<hyper::Uri, Response = TcpStream> + Send + 'static,
    C::Future: Send + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = SocketConnection;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|e| e.into())
    }

    fn call(&mut self, uri: hyper::Uri) -> Self::Future {
        let interface = self.interface.clone();
        let fut = self.inner.call(uri);

        Box::pin(async move {
            let tcp_stream = fut.await.map_err(|e| e.into())?;

            // 如果指定了接口，绑定到接口
            if let Some(iface) = interface {
                // 获取底层文件描述符
                let socket_fd = tcp_stream.as_raw_fd();

                // 创建 socket2::Socket
                let socket = unsafe { socket2::Socket::from_raw_fd(socket_fd) };

                // 绑定到指定接口
                if let Err(e) = socket.bind_device(Some(iface.as_bytes())) {
                    println!("Failed to bind to interface {}: {:?}", iface, e);
                }

                // 防止 socket 关闭
                std::mem::forget(socket);
            }

            Ok(SocketConnection { inner: tcp_stream })
        })
    }
}

// 封装 TcpStream 的连接类型
pub struct SocketConnection {
    inner: TcpStream,
}

impl Connection for SocketConnection {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AsyncRead for SocketConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SocketConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}