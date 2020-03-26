use std::net::SocketAddr;

use socks5x::{
    AuthenticationRequest, AuthenticationResponse, Command, Method, Replies, TcpRequestHeader,
};
use tokio::{
    io::{copy, AsyncWriteExt, ErrorKind, Result},
    net::{lookup_host, TcpListener, TcpStream},
};

pub struct Server(TcpStream);

impl Server {
    pub async fn run(addr: &str) -> Result<()> {
        let addr = lookup_host(addr)
            .await?
            .next()
            .ok_or(ErrorKind::AddrNotAvailable)?;
        let mut listener = TcpListener::bind(addr).await?;

        loop {
            let (stream, _) = listener.accept().await?;
            tokio::spawn(async move {
                let mut server: Server = stream.into();
                if let Err(e) = server.proxy().await {
                    if let Ok(log_level) = std::env::var("LOG_LEVEL") {
                        if log_level == "error" {
                            println!("error: {}", e);
                        }
                    }
                }
            });
        }
    }

    async fn proxy(&mut self) -> Result<()> {
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
                let addr = addr.to_socket_addrs().await?;
                let mut host_stream = match TcpStream::connect(addr).await {
                    Ok(s) => {
                        self.reply(Replies::Succeeded, addr).await?;
                        s
                    }
                    Err(e) => {
                        let error = e.kind().into();
                        self.reply(e.into(), addr).await?;
                        return Err(error);
                    }
                };
                let (mut host_r, mut host_w) = host_stream.split();
                let (mut r, mut w) = self.0.split();
                futures::future::select(copy(&mut r, &mut host_w), copy(&mut host_r, &mut w)).await;
                Ok(())
            }
            Command::LookupHost => {
                let addr = addr.to_socket_addrs().await?;
                self.reply(Replies::Succeeded, addr).await?;
                Ok(())
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
        self.0.write_all(bytes).await
    }
}

impl From<TcpStream> for Server {
    fn from(s: TcpStream) -> Server {
        Server(s)
    }
}
