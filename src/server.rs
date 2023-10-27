use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
};

use anyhow::{anyhow, Result};
use async_executor::Executor;
use async_io::{block_on, Async};
use futures_lite::{
    future::race,
    io::{copy, AsyncWriteExt},
};
use socks5::{
    AuthenticationRequest, AuthenticationResponse, Command, Method, Replies, TcpRequestHeader,
};

pub struct Server(Async<TcpStream>);

impl Server {
    pub fn run(addr: &str) -> Result<()> {
        let addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("invalid listen address"))?;
        let executor = Executor::new();
        block_on(executor.run(async {
            let listener = Async::<TcpListener>::bind(addr)?;
            loop {
                let (stream, _) = listener.accept().await?;
                let handler = executor.spawn(async move {
                    let server: Server = stream.into();
                    if let Err(e) = server.proxy().await {
                        println!("error: {}", e);
                    }
                });
                handler.await
            }
        }))
    }

    async fn proxy(mut self) -> Result<()> {
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
                let tcp_stream = self.0.get_ref();
                let rh = e
                    .clone()
                    .reply
                    .into_response(tcp_stream.peer_addr()?.into());
                self.write(&rh.to_bytes()).await?;
                return Err(e.into());
            }
        };
        let addr = header.address();
        match header.command() {
            Command::Connect => {
                let dest_addr = match addr.lookup(Self::lookup).await {
                    Ok(addr) => addr,
                    Err(e) => {
                        let resp = e.reply.into_response(addr.clone());
                        self.write(&resp.to_bytes()).await?;
                        return Err(e.into());
                    }
                };
                let dest_tcp = match Async::<TcpStream>::connect(dest_addr).await {
                    Ok(s) => {
                        self.reply(Replies::Succeeded, dest_addr).await?;
                        s
                    }
                    Err(e) => return Err(e.into()),
                };

                race(copy(&self.0, &dest_tcp), copy(&dest_tcp, &self.0))
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

    async fn lookup(name: &[u8]) -> std::io::Result<IpAddr> {
        let name = String::from_utf8_lossy(name);
        let addrs = async_dns::lookup(&name).await?;
        match addrs.into_iter().next() {
            Some(addr) => Ok(addr.ip_address),
            None => Err(ErrorKind::AddrNotAvailable.into()),
        }
    }
}

impl From<Async<TcpStream>> for Server {
    fn from(s: Async<TcpStream>) -> Server {
        Server(s)
    }
}
