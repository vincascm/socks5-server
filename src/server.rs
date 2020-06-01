use std::net::{SocketAddr, TcpListener, TcpStream};

use anyhow::Result;
use futures::{
    future::select,
    io::{copy, AsyncReadExt, AsyncWriteExt},
};
use smol::{Async, Task};
use socks5::{
    AuthenticationRequest, AuthenticationResponse, Command, Method, Replies, TcpRequestHeader,
};

pub struct Server(Async<TcpStream>);

impl Server {
    pub fn run(addr: &str) -> Result<()> {
        smol::run(async {
            let listener = Async::<TcpListener>::bind(addr)?;

            loop {
                let (stream, _) = listener.accept().await?;
                Task::spawn(async move {
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
                let rh = e
                    .clone()
                    .reply
                    .into_response(self.0.get_ref().peer_addr()?.into());
                self.write(&rh.to_bytes()).await?;
                return Err(e.into());
            }
        };
        let addr = header.address();
        match header.command() {
            Command::Connect => {
                let addr = addr.clone().to_socket_addrs().await?;
                let host_stream = match Async::<TcpStream>::connect(addr).await {
                    Ok(s) => {
                        self.reply(Replies::Succeeded, addr).await?;
                        s
                    }
                    Err(e) => return Err(e.into()),
                };
                let (mut host_r, mut host_w) = host_stream.split();
                let (mut r, mut w) = self.0.split();
                select(copy(&mut r, &mut host_w), copy(&mut host_r, &mut w)).await;
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
        Ok(self.0.write_all(bytes).await?)
    }
}

impl From<Async<TcpStream>> for Server {
    fn from(s: Async<TcpStream>) -> Server {
        Server(s)
    }
}
