use anyhow::{anyhow, Result};
use smol::{
    block_on,
    future::{race, FutureExt},
    io::{copy, AsyncWriteExt},
    net::{SocketAddr, TcpListener, TcpStream},
    spawn, Timer,
};
use socks5::{
    AuthenticationRequest, AuthenticationResponse, Command, Method, Replies, TcpRequestHeader,
};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(180);

pub struct Server(TcpStream);

impl Server {
    pub fn run(addr: &str) -> Result<()> {
        block_on(async {
            let listener = TcpListener::bind(addr).await?;
            loop {
                let (stream, _) = listener.accept().await?;
                spawn(async move {
                    let server: Server = stream.into();
                    if let Err(e) = server.proxy().await {
                        println!("error: {}", e);
                    }
                })
                .detach();
            }
        })
    }

    async fn proxy(mut self) -> Result<()> {
        self.0.set_nodelay(true)?;
        // authentication
        let authentication_request = AuthenticationRequest::read_from(&mut self.0).await?;
        let authentication_response: AuthenticationResponse =
            if authentication_request.required_authentication() {
                Method::NotAcceptable.into()
            } else {
                Method::NONE.into()
            };
        self.write(&authentication_response.to_bytes()).await?;

        // requests
        let header = match TcpRequestHeader::read_from(&mut self.0).await {
            Ok(h) => h,
            Err(e) => {
                let rh = e.clone().reply.into_response(self.0.peer_addr()?.into());
                self.write(&rh.to_bytes()).await?;
                return Err(e.into());
            }
        };
        let addr = header.address();
        match header.command() {
            Command::Connect => {
                let dest_addr = match addr.to_socket_addr().await {
                    Ok(addr) => addr,
                    Err(e) => {
                        let resp = e.reply.into_response(addr.clone());
                        self.write(&resp.to_bytes()).await?;
                        return Err(e.into());
                    }
                };
                let dest_tcp = match TcpStream::connect(dest_addr).await {
                    Ok(s) => {
                        self.reply(Replies::Succeeded, dest_addr).await?;
                        s
                    }
                    Err(e) => return Err(e.into()),
                };

                let left = copy(&self.0, &dest_tcp).or(async { Self::timeout().await });
                let right = copy(&dest_tcp, &self.0).or(async { Self::timeout().await });
                race(left, right)
                    .await
                    .map(|_| ())
                    .map_err(|_| anyhow!("io error"))
            }
            // Bind and UdpAssociate, is not supported
            _ => {
                let rh = Replies::CommandNotSupported.into_response(addr.clone());
                self.write(&rh.to_bytes()).await
            }
        }
    }

    async fn reply(&mut self, reply: Replies, addr: SocketAddr) -> Result<()> {
        let header = reply.into_response(addr.into());
        self.write(&header.to_bytes()).await
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.0.write_all(bytes).await?;
        Ok(self.0.flush().await?)
    }

    async fn timeout() -> Result<u64, std::io::Error> {
        Timer::after(TIMEOUT).await;
        Err(std::io::ErrorKind::TimedOut.into())
    }
}

impl From<TcpStream> for Server {
    fn from(s: TcpStream) -> Server {
        Server(s)
    }
}
