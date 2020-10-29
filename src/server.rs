use std::{
    convert::TryInto,
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
};

use anyhow::{anyhow, Result};
use smol::{
    block_on,
    future::race,
    io::{copy, AsyncWriteExt},
    spawn, unblock, Async,
};
use socks5::{
    AuthenticationRequest, AuthenticationResponse, Command, Error, Method, Replies,
    TcpRequestHeader,
};

pub struct Server(Async<TcpStream>);

impl Server {
    pub fn run(addr: &str) -> Result<()> {
        let addr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow!("invalid listen address"))?;
        block_on(async {
            let listener = Async::<TcpListener>::bind(addr)?;
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
                let dest_addr: Result<_, Error> = {
                    let addr = addr.clone();
                    unblock(|| addr.try_into()).await
                };
                let dest_addr = match dest_addr {
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
}

impl From<Async<TcpStream>> for Server {
    fn from(s: Async<TcpStream>) -> Server {
        Server(s)
    }
}
